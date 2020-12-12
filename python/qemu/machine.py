"""
QEMU machine module:

The machine module primarily provides the QEMUMachine class,
which provides facilities for managing the lifetime of a QEMU VM.
"""

# Copyright (C) 2015-2016 Red Hat Inc.
# Copyright (C) 2012 IBM Corp.
#
# Authors:
#  Fam Zheng <famz@redhat.com>
#
# This work is licensed under the terms of the GNU GPL, version 2.  See
# the COPYING file in the top-level directory.
#
# Based on qmp.py.
#

import errno
from itertools import chain
import logging
import os
import shutil
import signal
import socket
import subprocess
import tempfile
from types import TracebackType
from typing import (
    Any,
    BinaryIO,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
)

from . import console_socket, qmp
from .qmp import QMPMessage, QMPReturnValue, SocketAddrT


LOG = logging.getLogger(__name__)


class QEMUMachineError(Exception):
    """
    Exception called when an error in QEMUMachine happens.
    """


class QEMUMachineAddDeviceError(QEMUMachineError):
    """
    Exception raised when a request to add a device can not be fulfilled

    The failures are caused by limitations, lack of information or conflicting
    requests on the QEMUMachine methods.  This exception does not represent
    failures reported by the QEMU binary itself.
    """


class AbnormalShutdown(QEMUMachineError):
    """
    Exception raised when a graceful shutdown was requested, but not performed.
    """


class QEMUMachine:
    """
    A QEMU VM.

    Use this object as a context manager to ensure
    the QEMU process terminates::

        with VM(binary) as vm:
            ...
        # vm is guaranteed to be shut down here
    """

    def __init__(self,
                 binary: str,
                 args: Sequence[str] = (),
                 wrapper: Sequence[str] = (),
                 name: Optional[str] = None,
                 test_dir: str = "/var/tmp",
                 monitor_address: Optional[SocketAddrT] = None,
                 socket_scm_helper: Optional[str] = None,
                 sock_dir: Optional[str] = None,
                 drain_console: bool = False,
                 console_log: Optional[str] = None):
        '''
        Initialize a QEMUMachine

        @param binary: path to the qemu binary
        @param args: list of extra arguments
        @param wrapper: list of arguments used as prefix to qemu binary
        @param name: prefix for socket and log file names (default: qemu-PID)
        @param test_dir: where to create socket and log file
        @param monitor_address: address for QMP monitor
        @param socket_scm_helper: helper program, required for send_fd_scm()
        @param sock_dir: where to create socket (overrides test_dir for sock)
        @param drain_console: (optional) True to drain console socket to buffer
        @param console_log: (optional) path to console log file
        @note: Qemu process is not started until launch() is used.
        '''
        # Direct user configuration

        self._binary = binary
        self._args = list(args)
        self._wrapper = wrapper

        self._name = name or "qemu-%d" % os.getpid()
        self._test_dir = test_dir
        self._sock_dir = sock_dir or self._test_dir
        self._socket_scm_helper = socket_scm_helper

        if monitor_address is not None:
            self._monitor_address = monitor_address
            self._remove_monitor_sockfile = False
        else:
            self._monitor_address = os.path.join(
                self._sock_dir, f"{self._name}-monitor.sock"
            )
            self._remove_monitor_sockfile = True

        self._console_log_path = console_log
        if self._console_log_path:
            # In order to log the console, buffering needs to be enabled.
            self._drain_console = True
        else:
            self._drain_console = drain_console

        # Runstate
        self._qemu_log_path: Optional[str] = None
        self._qemu_log_file: Optional[BinaryIO] = None
        self._popen: Optional['subprocess.Popen[bytes]'] = None
        self._events: List[QMPMessage] = []
        self._iolog: Optional[str] = None
        self._qmp_set = True   # Enable QMP monitor by default.
        self._qmp_connection: Optional[qmp.QEMUMonitorProtocol] = None
        self._qemu_full_args: Tuple[str, ...] = ()
        self._temp_dir: Optional[str] = None
        self._launched = False
        self._machine: Optional[str] = None
        self._console_index = 0
        self._console_set = False
        self._console_device_type: Optional[str] = None
        self._console_address = os.path.join(
            self._sock_dir, f"{self._name}-console.sock"
        )
        self._console_socket: Optional[socket.socket] = None
        self._remove_files: List[str] = []
        self._user_killed = False

    def __enter__(self) -> 'QEMUMachine':
        return self

    def __exit__(self,
                 exc_type: Optional[Type[BaseException]],
                 exc_val: Optional[BaseException],
                 exc_tb: Optional[TracebackType]) -> None:
        self.shutdown()

    def add_monitor_null(self) -> None:
        """
        This can be used to add an unused monitor instance.
        """
        self._args.append('-monitor')
        self._args.append('null')

    def add_fd(self, fd: int, fdset: int,
               opaque: str, opts: str = '') -> 'QEMUMachine':
        """
        Pass a file descriptor to the VM
        """
        options = ['fd=%d' % fd,
                   'set=%d' % fdset,
                   'opaque=%s' % opaque]
        if opts:
            options.append(opts)

        # This did not exist before 3.4, but since then it is
        # mandatory for our purpose
        if hasattr(os, 'set_inheritable'):
            os.set_inheritable(fd, True)

        self._args.append('-add-fd')
        self._args.append(','.join(options))
        return self

    def send_fd_scm(self, fd: Optional[int] = None,
                    file_path: Optional[str] = None) -> int:
        """
        Send an fd or file_path to socket_scm_helper.

        Exactly one of fd and file_path must be given.
        If it is file_path, the helper will open that file and pass its own fd.
        """
        # In iotest.py, the qmp should always use unix socket.
        assert self._qmp.is_scm_available()
        if self._socket_scm_helper is None:
            raise QEMUMachineError("No path to socket_scm_helper set")
        if not os.path.exists(self._socket_scm_helper):
            raise QEMUMachineError("%s does not exist" %
                                   self._socket_scm_helper)

        # This did not exist before 3.4, but since then it is
        # mandatory for our purpose
        if hasattr(os, 'set_inheritable'):
            os.set_inheritable(self._qmp.get_sock_fd(), True)
            if fd is not None:
                os.set_inheritable(fd, True)

        fd_param = ["%s" % self._socket_scm_helper,
                    "%d" % self._qmp.get_sock_fd()]

        if file_path is not None:
            assert fd is None
            fd_param.append(file_path)
        else:
            assert fd is not None
            fd_param.append(str(fd))

        devnull = open(os.path.devnull, 'rb')
        proc = subprocess.Popen(
            fd_param, stdin=devnull, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, close_fds=False
        )
        output = proc.communicate()[0]
        if output:
            LOG.debug(output)

        return proc.returncode

    @staticmethod
    def _remove_if_exists(path: str) -> None:
        """
        Remove file object at path if it exists
        """
        try:
            os.remove(path)
        except OSError as exception:
            if exception.errno == errno.ENOENT:
                return
            raise

    def is_running(self) -> bool:
        """Returns true if the VM is running."""
        return self._popen is not None and self._popen.poll() is None

    @property
    def _subp(self) -> 'subprocess.Popen[bytes]':
        if self._popen is None:
            raise QEMUMachineError('Subprocess pipe not present')
        return self._popen

    def exitcode(self) -> Optional[int]:
        """Returns the exit code if possible, or None."""
        if self._popen is None:
            return None
        return self._popen.poll()

    def get_pid(self) -> Optional[int]:
        """Returns the PID of the running process, or None."""
        if not self.is_running():
            return None
        return self._subp.pid

    def _load_io_log(self) -> None:
        if self._qemu_log_path is not None:
            with open(self._qemu_log_path, "r") as iolog:
                self._iolog = iolog.read()

    @property
    def _base_args(self) -> List[str]:
        args = ['-display', 'none', '-vga', 'none']

        if self._qmp_set:
            if isinstance(self._monitor_address, tuple):
                moncdev = "socket,id=mon,host={},port={}".format(
                    *self._monitor_address
                )
            else:
                moncdev = f"socket,id=mon,path={self._monitor_address}"
            args.extend(['-chardev', moncdev, '-mon',
                         'chardev=mon,mode=control'])

        if self._machine is not None:
            args.extend(['-machine', self._machine])
        for _ in range(self._console_index):
            args.extend(['-serial', 'null'])
        if self._console_set:
            chardev = ('socket,id=console,path=%s,server,nowait' %
                       self._console_address)
            args.extend(['-chardev', chardev])
            if self._console_device_type is None:
                args.extend(['-serial', 'chardev:console'])
            else:
                device = '%s,chardev=console' % self._console_device_type
                args.extend(['-device', device])
        return args

    def _pre_launch(self) -> None:
        self._temp_dir = tempfile.mkdtemp(prefix="qemu-machine-",
                                          dir=self._test_dir)
        self._qemu_log_path = os.path.join(self._temp_dir, self._name + ".log")
        self._qemu_log_file = open(self._qemu_log_path, 'wb')

        if self._console_set:
            self._remove_files.append(self._console_address)

        if self._qmp_set:
            if self._remove_monitor_sockfile:
                assert isinstance(self._monitor_address, str)
                self._remove_files.append(self._monitor_address)
            self._qmp_connection = qmp.QEMUMonitorProtocol(
                self._monitor_address,
                server=True,
                nickname=self._name
            )

    def _post_launch(self) -> None:
        if self._qmp_connection:
            self._qmp.accept()

    def _post_shutdown(self) -> None:
        """
        Called to cleanup the VM instance after the process has exited.
        May also be called after a failed launch.
        """
        # Comprehensive reset for the failed launch case:
        self._early_cleanup()

        if self._qmp_connection:
            self._qmp.close()
            self._qmp_connection = None

        self._load_io_log()

        if self._qemu_log_file is not None:
            self._qemu_log_file.close()
            self._qemu_log_file = None

        self._qemu_log_path = None

        if self._temp_dir is not None:
            shutil.rmtree(self._temp_dir)
            self._temp_dir = None

        while len(self._remove_files) > 0:
            self._remove_if_exists(self._remove_files.pop())

        exitcode = self.exitcode()
        if (exitcode is not None and exitcode < 0
                and not (self._user_killed and exitcode == -signal.SIGKILL)):
            msg = 'qemu received signal %i; command: "%s"'
            if self._qemu_full_args:
                command = ' '.join(self._qemu_full_args)
            else:
                command = ''
            LOG.warning(msg, -int(exitcode), command)

        self._user_killed = False
        self._launched = False

    def launch(self) -> None:
        """
        Launch the VM and make sure we cleanup and expose the
        command line/output in case of exception
        """

        if self._launched:
            raise QEMUMachineError('VM already launched')

        self._iolog = None
        self._qemu_full_args = ()
        try:
            self._launch()
            self._launched = True
        except:
            self._post_shutdown()

            LOG.debug('Error launching VM')
            if self._qemu_full_args:
                LOG.debug('Command: %r', ' '.join(self._qemu_full_args))
            if self._iolog:
                LOG.debug('Output: %r', self._iolog)
            raise

    def _launch(self) -> None:
        """
        Launch the VM and establish a QMP connection
        """
        devnull = open(os.path.devnull, 'rb')
        self._pre_launch()
        self._qemu_full_args = tuple(
            chain(self._wrapper,
                  [self._binary],
                  self._base_args,
                  self._args)
        )
        LOG.debug('VM launch command: %r', ' '.join(self._qemu_full_args))
        self._popen = subprocess.Popen(self._qemu_full_args,
                                       stdin=devnull,
                                       stdout=self._qemu_log_file,
                                       stderr=subprocess.STDOUT,
                                       shell=False,
                                       close_fds=False)
        self._post_launch()

    def _early_cleanup(self) -> None:
        """
        Perform any cleanup that needs to happen before the VM exits.

        May be invoked by both soft and hard shutdown in failover scenarios.
        Called additionally by _post_shutdown for comprehensive cleanup.
        """
        # If we keep the console socket open, we may deadlock waiting
        # for QEMU to exit, while QEMU is waiting for the socket to
        # become writeable.
        if self._console_socket is not None:
            self._console_socket.close()
            self._console_socket = None

    def _hard_shutdown(self) -> None:
        """
        Perform early cleanup, kill the VM, and wait for it to terminate.

        :raise subprocess.Timeout: When timeout is exceeds 60 seconds
            waiting for the QEMU process to terminate.
        """
        self._early_cleanup()
        self._subp.kill()
        self._subp.wait(timeout=60)

    def _soft_shutdown(self, timeout: Optional[int],
                       has_quit: bool = False) -> None:
        """
        Perform early cleanup, attempt to gracefully shut down the VM, and wait
        for it to terminate.

        :param timeout: Timeout in seconds for graceful shutdown.
                        A value of None is an infinite wait.
        :param has_quit: When True, don't attempt to issue 'quit' QMP command

        :raise ConnectionReset: On QMP communication errors
        :raise subprocess.TimeoutExpired: When timeout is exceeded waiting for
            the QEMU process to terminate.
        """
        self._early_cleanup()

        if self._qmp_connection:
            if not has_quit:
                # Might raise ConnectionReset
                self._qmp.cmd('quit')

        # May raise subprocess.TimeoutExpired
        self._subp.wait(timeout=timeout)

    def _do_shutdown(self, timeout: Optional[int],
                     has_quit: bool = False) -> None:
        """
        Attempt to shutdown the VM gracefully; fallback to a hard shutdown.

        :param timeout: Timeout in seconds for graceful shutdown.
                        A value of None is an infinite wait.
        :param has_quit: When True, don't attempt to issue 'quit' QMP command

        :raise AbnormalShutdown: When the VM could not be shut down gracefully.
            The inner exception will likely be ConnectionReset or
            subprocess.TimeoutExpired. In rare cases, non-graceful termination
            may result in its own exceptions, likely subprocess.TimeoutExpired.
        """
        try:
            self._soft_shutdown(timeout, has_quit)
        except Exception as exc:
            self._hard_shutdown()
            raise AbnormalShutdown("Could not perform graceful shutdown") \
                from exc

    def shutdown(self, has_quit: bool = False,
                 hard: bool = False,
                 timeout: Optional[int] = 30) -> None:
        """
        Terminate the VM (gracefully if possible) and perform cleanup.
        Cleanup will always be performed.

        If the VM has not yet been launched, or shutdown(), wait(), or kill()
        have already been called, this method does nothing.

        :param has_quit: When true, do not attempt to issue 'quit' QMP command.
        :param hard: When true, do not attempt graceful shutdown, and
                     suppress the SIGKILL warning log message.
        :param timeout: Optional timeout in seconds for graceful shutdown.
                        Default 30 seconds, A `None` value is an infinite wait.
        """
        if not self._launched:
            return

        try:
            if hard:
                self._user_killed = True
                self._hard_shutdown()
            else:
                self._do_shutdown(timeout, has_quit)
        finally:
            self._post_shutdown()

    def kill(self) -> None:
        """
        Terminate the VM forcefully, wait for it to exit, and perform cleanup.
        """
        self.shutdown(hard=True)

    def wait(self, timeout: Optional[int] = 30) -> None:
        """
        Wait for the VM to power off and perform post-shutdown cleanup.

        :param timeout: Optional timeout in seconds. Default 30 seconds.
                        A value of `None` is an infinite wait.
        """
        self.shutdown(has_quit=True, timeout=timeout)

    def set_qmp_monitor(self, enabled: bool = True) -> None:
        """
        Set the QMP monitor.

        @param enabled: if False, qmp monitor options will be removed from
                        the base arguments of the resulting QEMU command
                        line. Default is True.
        @note: call this function before launch().
        """
        self._qmp_set = enabled

    @property
    def _qmp(self) -> qmp.QEMUMonitorProtocol:
        if self._qmp_connection is None:
            raise QEMUMachineError("Attempt to access QMP with no connection")
        return self._qmp_connection

    @classmethod
    def _qmp_args(cls, _conv_keys: bool = True, **args: Any) -> Dict[str, Any]:
        qmp_args = dict()
        for key, value in args.items():
            if _conv_keys:
                qmp_args[key.replace('_', '-')] = value
            else:
                qmp_args[key] = value
        return qmp_args

    def qmp(self, cmd: str,
            conv_keys: bool = True,
            **args: Any) -> QMPMessage:
        """
        Invoke a QMP command and return the response dict
        """
        qmp_args = self._qmp_args(conv_keys, **args)
        return self._qmp.cmd(cmd, args=qmp_args)

    def command(self, cmd: str,
                conv_keys: bool = True,
                **args: Any) -> QMPReturnValue:
        """
        Invoke a QMP command.
        On success return the response dict.
        On failure raise an exception.
        """
        qmp_args = self._qmp_args(conv_keys, **args)
        return self._qmp.command(cmd, **qmp_args)

    def get_qmp_event(self, wait: bool = False) -> Optional[QMPMessage]:
        """
        Poll for one queued QMP events and return it
        """
        if self._events:
            return self._events.pop(0)
        return self._qmp.pull_event(wait=wait)

    def get_qmp_events(self, wait: bool = False) -> List[QMPMessage]:
        """
        Poll for queued QMP events and return a list of dicts
        """
        events = self._qmp.get_events(wait=wait)
        events.extend(self._events)
        del self._events[:]
        self._qmp.clear_events()
        return events

    @staticmethod
    def event_match(event: Any, match: Optional[Any]) -> bool:
        """
        Check if an event matches optional match criteria.

        The match criteria takes the form of a matching subdict. The event is
        checked to be a superset of the subdict, recursively, with matching
        values whenever the subdict values are not None.

        This has a limitation that you cannot explicitly check for None values.

        Examples, with the subdict queries on the left:
         - None matches any object.
         - {"foo": None} matches {"foo": {"bar": 1}}
         - {"foo": None} matches {"foo": 5}
         - {"foo": {"abc": None}} does not match {"foo": {"bar": 1}}
         - {"foo": {"rab": 2}} matches {"foo": {"bar": 1, "rab": 2}}
        """
        if match is None:
            return True

        try:
            for key in match:
                if key in event:
                    if not QEMUMachine.event_match(event[key], match[key]):
                        return False
                else:
                    return False
            return True
        except TypeError:
            # either match or event wasn't iterable (not a dict)
            return bool(match == event)

    def event_wait(self, name: str,
                   timeout: float = 60.0,
                   match: Optional[QMPMessage] = None) -> Optional[QMPMessage]:
        """
        event_wait waits for and returns a named event from QMP with a timeout.

        name: The event to wait for.
        timeout: QEMUMonitorProtocol.pull_event timeout parameter.
        match: Optional match criteria. See event_match for details.
        """
        return self.events_wait([(name, match)], timeout)

    def events_wait(self,
                    events: Sequence[Tuple[str, Any]],
                    timeout: float = 60.0) -> Optional[QMPMessage]:
        """
        events_wait waits for and returns a single named event from QMP.
        In the case of multiple qualifying events, this function returns the
        first one.

        :param events: A sequence of (name, match_criteria) tuples.
                       The match criteria are optional and may be None.
                       See event_match for details.
        :param timeout: Optional timeout, in seconds.
                        See QEMUMonitorProtocol.pull_event.

        :raise QMPTimeoutError: If timeout was non-zero and no matching events
                                were found.
        :return: A QMP event matching the filter criteria.
                 If timeout was 0 and no event matched, None.
        """
        def _match(event: QMPMessage) -> bool:
            for name, match in events:
                if event['event'] == name and self.event_match(event, match):
                    return True
            return False

        event: Optional[QMPMessage]

        # Search cached events
        for event in self._events:
            if _match(event):
                self._events.remove(event)
                return event

        # Poll for new events
        while True:
            event = self._qmp.pull_event(wait=timeout)
            if event is None:
                # NB: None is only returned when timeout is false-ish.
                # Timeouts raise QMPTimeoutError instead!
                break
            if _match(event):
                return event
            self._events.append(event)

        return None

    def get_log(self) -> Optional[str]:
        """
        After self.shutdown or failed qemu execution, this returns the output
        of the qemu process.
        """
        return self._iolog

    def add_args(self, *args: str) -> None:
        """
        Adds to the list of extra arguments to be given to the QEMU binary
        """
        self._args.extend(args)

    def set_machine(self, machine_type: str) -> None:
        """
        Sets the machine type

        If set, the machine type will be added to the base arguments
        of the resulting QEMU command line.
        """
        self._machine = machine_type

    def set_console(self,
                    device_type: Optional[str] = None,
                    console_index: int = 0) -> None:
        """
        Sets the device type for a console device

        If set, the console device and a backing character device will
        be added to the base arguments of the resulting QEMU command
        line.

        This is a convenience method that will either use the provided
        device type, or default to a "-serial chardev:console" command
        line argument.

        The actual setting of command line arguments will be be done at
        machine launch time, as it depends on the temporary directory
        to be created.

        @param device_type: the device type, such as "isa-serial".  If
                            None is given (the default value) a "-serial
                            chardev:console" command line argument will
                            be used instead, resorting to the machine's
                            default device type.
        @param console_index: the index of the console device to use.
                              If not zero, the command line will create
                              'index - 1' consoles and connect them to
                              the 'null' backing character device.
        """
        self._console_set = True
        self._console_device_type = device_type
        self._console_index = console_index

    @property
    def console_socket(self) -> socket.socket:
        """
        Returns a socket connected to the console
        """
        if self._console_socket is None:
            self._console_socket = console_socket.ConsoleSocket(
                self._console_address,
                file=self._console_log_path,
                drain=self._drain_console)
        return self._console_socket
