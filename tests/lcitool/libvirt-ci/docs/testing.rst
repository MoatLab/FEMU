=======
Testing
=======

This project utilizes the pytest framework. Make sure you add a new test case
with any new logic you introduce to the lcitool code base.
Whenever you add new package mappings the test suite will naturally fail
because it simply doesn't know about them. In that case, just re-run the test
suite as

::

    $ python3 -m pytest --regenerate-output

and the expected package data sets will be updated. You can then just grab the
changes and add them to your commit. Beware though that if you test a buggy
code this way the tests would not be able to catch regressions since the
"correct" test output would now match the flawed output.
