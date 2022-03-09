help-usage
==========

This is an example task for `Taskotron <https://fedoraproject.org/wiki/Taskotron>`_
that tests the basic functionality of 'sscg --help' to confirm it generates a usage message.

Standalone you can run it like this::

  $ make run

Through taskotron runner you can run it like this::

  $ runtask -i sscg-2.0.4-1.fc27 -t koji_build -a x86_64 runtask.yml
