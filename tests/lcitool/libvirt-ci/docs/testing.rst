=======
Testing
=======

Running tests
-------------
This project utilizes the pytest framework. You can either run it directly
yourself or make use of the power of tox and test in different environments.

Pytest
~~~~~~

You can run a smoke check of your changes quickly with

::

    $ pytest

For more extensive checking in different environments please consider using
tox, see below.

Tox
~~~
Make sure you have tox installed for this one. You can either install it
manually or via ``dev-requirements.txt`` which will also install all
dependencies for overall lcitool development. Once installed, simply run

::

    $ tox

Running specific test environments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We define a couple of test environments for tox:

* ``lint`` flake8 linter
* ``py38`` which reflects our minimum requirement for Python 3.8
* ``py311`` which is supposed to catch early deprecations with latest Python

You can select which test environment tox should execute with

::

    $ tox -e <test_env>


Adding test cases
-----------------
Make sure you add a new test case with any new logic you introduce to the
lcitool code base. Note that whenever you add new package mappings the test
suite will naturally fail because it simply doesn't know about them. In that
case, just re-run the test suite as

::

    $ pytest --regenerate-output

or

::

    $ tox -e py38 -- --regenerate-output

depending on what tool you prefer for testing and the expected package data
sets will be updated automatically. You can then just grab the changes and add
them to your commit. Beware though that if you test a buggy code this way the
tests would not be able to catch regressions since the "correct" test output
would now match the flawed output. Note however that when regenerating output
with ``tox`` you **must** select a test environment with ``tox`` because
otherwise all environments will get the ``--regenerate-output`` option which
could make some of them fail.
