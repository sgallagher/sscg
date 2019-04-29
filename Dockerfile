FROM sgallagh/sscg-deps

MAINTAINER Stephen Gallagher <sgallagh@redhat.com>

ARG TARBALL

ADD $TARBALL /builddir/

RUN  /builddir/.travis/coverity_prep.sh

ENTRYPOINT /builddir/.travis/travis-tasks.sh
