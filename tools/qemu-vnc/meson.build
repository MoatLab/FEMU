vnca = vnc_ss.apply({}, strict: false)

qemu_vnc1 = custom_target('qemu-vnc1 gdbus-codegen',
                           output: ['qemu-vnc1.h', 'qemu-vnc1.c'],
                           input: files('qemu-vnc1.xml'),
                           command: [gdbus_codegen, '@INPUT@',
                                     '--glib-min-required', '2.64',
                                     '--output-directory', meson.current_build_dir(),
                                     '--interface-prefix', 'org.qemu.',
                                     '--c-namespace', 'Qemu',
                                     '--generate-c-code', '@BASENAME@'])

qemu_vnc = executable('qemu-vnc',
  sources: ['qemu-vnc.c', 'display.c', 'input.c',
            'audio.c', 'chardev.c', 'clipboard.c', 'console.c',
            'dbus.c', 'stubs.c', 'utils.c',
            vnca.sources(), dbus_display1, qemu_vnc1],
  dependencies: [vnca.dependencies(), io, crypto, qemuutil, gio, ui])

# The executable lives in a subdirectory of the build tree, but
# get_relocated_path() looks for qemu-bundle relative to the binary.
# Create a symlink so that firmware/keymap lookup works during development.
run_command('ln', '-sfn',
            '../../qemu-bundle',
            meson.current_build_dir() / 'qemu-bundle',
            check: false)
