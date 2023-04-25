# gitlab.py - helpers for generating CI rules from templates
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import textwrap

#
# The job templates in this file rely on variables in a
# number of namespaces
#
#  - CI_nnn - standard variables defined by GitLab
#
#  - CIRRUS_nnn - variables for controlling Cirrus CI
#    job integration
#
#  - RUN_nnn - variables for a maintainer to set when
#    triggering a  pipeline
#
#  - JOB_nnn - variables set against jobs which influence
#    rules in templates they inherit from
#


def docs(namespace):
    return textwrap.dedent(
        f"""
        # Variables that can be set to control the behaviour of
        # pipelines that are run
        #
        #  - RUN_PIPELINE - force creation of a CI pipeline when
        #    pushing to a branch in a forked repository. Official
        #    CI pipelines are triggered when merge requests are
        #    created/updated. Setting this variable to a non-empty
        #    value allows CI testing prior to opening a merge request.
        #
        #  - RUN_PIPELINE_UPSTREAM_ENV - same semantics as RUN_PIPELINE,
        #    but uses the CI environment (containers) from the upstream project
        #    rather than creating and updating a throwaway environment
        #    Should not be used if the pushed branch includes CI container
        #    changes.
        #
        #  - RUN_CONTAINER_BUILDS - CI pipelines in upstream only
        #    publish containers if CI file changes are detected.
        #    Setting this variable to a non-empty value will force
        #    re-publishing, even when no file changes are detected.
        #    Typically to use from a scheduled job once a month.
        #
        #  - RUN_UPSTREAM_NAMESPACE - the upstream namespace is
        #    configured to default to '{namespace}'. When testing
        #    changes to CI it might be useful to use a different
        #    upstream. Setting this variable will override the
        #    namespace considered to be upstream.
        #
        # These can be set as git push options
        #
        #  $ git push -o ci.variable=RUN_PIPELINE=1
        #
        # Aliases can be set for common usage
        #
        #  $ git config --local alias.push-ci "push -o ci.variable=RUN_PIPELINE=1"
        #
        # Allowing the less verbose invocation
        #
        #  $ git push-ci
        #
        # Pipeline variables can also be set in the repository
        # pipeline config globally, or set against scheduled pipelines
        """)


def variables(namespace):
    return textwrap.dedent(
        f"""
        variables:
          RUN_UPSTREAM_NAMESPACE: {namespace}
          FF_SCRIPT_SECTIONS: 1
        """)


def workflow():
    return textwrap.dedent(
        """
        workflow:
          rules:
            # upstream+forks: Avoid duplicate pipelines on pushes, if a MR is open
            - if: '$CI_PIPELINE_SOURCE == "push" && $CI_OPEN_MERGE_REQUESTS'
              when: never

            # upstream+forks: Avoid pipelines on tag pushes
            - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_TAG'
              when: never

            # upstream+forks: Allow pipelines in scenarios we've figured out job rules
            - if: '$CI_PIPELINE_SOURCE =~ /^(push|merge_request_event|api|web|schedule)$/'
              when: always

            # upstream+forks: Avoid all other pipelines
            - when: never
        """)


def debug():
    return textwrap.dedent(
        """
        debug:
          image: docker.io/library/alpine:3
          stage: sanity_checks
          interruptible: true
          needs: []
          script:
            - printenv | sort
          rules:
            - if: '$RUN_DEBUG'
              when: always
        """)


def includes(paths):
    lines = [f"  - local: '/{path}'" for path in paths]
    return "include:\n" + "\n".join(lines)


def format_variables(variables):
    job = []
    for key in sorted(variables.keys()):
        val = variables[key]
        job.append(f"    {key}: {val}")
    if len(job) > 0:
        return "  variables:\n" + "\n".join(job) + "\n"
    return ""


def container_template(cidir):
    return textwrap.dedent(
        f"""
        # We want to publish containers with tag 'latest':
        #
        #  - In upstream, for push to default branch with CI changes.
        #  - In upstream, on request, for scheduled/manual pipelines
        #    against default branch
        #
        # Note: never publish from merge requests since they have non-committed code
        #
        .container_job:
          image: docker:stable
          stage: containers
          interruptible: false
          needs: []
          services:
            - docker:dind
          before_script:
            - export TAG="$CI_REGISTRY_IMAGE/ci-$NAME:latest"
            - docker info
            - docker login "$CI_REGISTRY" -u "$CI_REGISTRY_USER" -p "$CI_REGISTRY_PASSWORD"
          script:
            - docker build --tag "$TAG" -f "{cidir}/containers/$NAME.Dockerfile" {cidir}/containers ;
            - docker push "$TAG"
          after_script:
            - docker logout
          rules:
            # upstream: publish containers if there were CI changes on the default branch
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
              when: on_success
              changes:
                - {cidir}/gitlab/container-templates.yml
                - {cidir}/containers/$NAME.Dockerfile

            # upstream: allow force re-publishing containers on default branch for web/api/scheduled pipelines
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE =~ /(web|api|schedule)/ && $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH && $RUN_CONTAINER_BUILDS == "1"'
              when: on_success

            # upstream+forks: that's all folks
            - when: never
        """)


def _build_template(template, image, project, cidir):
    return textwrap.dedent(
        f"""
        #
        # We use pre-built containers for any pipelines that are:
        #
        #  - Validating code committed on default upstream branch
        #  - Validating patches targeting default upstream branch
        #    which do not have CI changes
        #
        # We use a local build env for any pipelines that are:
        #
        #  - Validating code committed to a non-default upstream branch
        #  - Validating patches targeting a non-default upstream branch
        #  - Validating patches targeting default upstream branch which
        #    include CI changes
        #  - Validating code committed to a fork branch
        #
        # Note: the rules across the prebuilt_env and local_env templates
        # should be logical inverses, such that jobs are mutually exclusive
        #
        {template}_prebuilt_env:
          image: $CI_REGISTRY/$RUN_UPSTREAM_NAMESPACE/{project}/{image}:latest
          stage: builds
          interruptible: true
          before_script:
            - cat /packages.txt
          rules:
            # upstream: pushes to the default branch
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
              when: on_success

            # forks: pushes to a branch when a pipeline run in upstream env is explicitly requested
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE_UPSTREAM_ENV && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE_UPSTREAM_ENV'
              when: on_success

            # upstream: other web/api/scheduled pipelines targeting the default branch
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE =~ /(web|api|schedule)/ && $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE =~ /(web|api|schedule)/ && $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH'
              when: on_success

            # upstream+forks: merge requests targeting the default branch, without CI changes
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH'
              changes:
                - {cidir}/gitlab/container-templates.yml
                - {cidir}/containers/$NAME.Dockerfile
              when: never
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH'
              when: on_success

            # upstream+forks: that's all folks
            - when: never

        {template}_local_env:
          image: $IMAGE
          stage: builds
          interruptible: true
          before_script:
            - source {cidir}/buildenv/$NAME.sh
            - install_buildenv
            - cat /packages.txt
          rules:
            # upstream: pushes to a non-default branch
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH'
              when: on_success

            # forks: avoid build in local env when job requests run in upstream containers
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE_UPSTREAM_ENV'
              when: never

            # forks: pushes to branches with pipeline requested
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE'
              when: on_success

            # upstream: other web/api/scheduled pipelines targeting non-default branches
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE =~ /(web|api|schedule)/ && $CI_COMMIT_REF_NAME != $CI_DEFAULT_BRANCH && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE =~ /(web|api|schedule)/ && $CI_COMMIT_REF_NAME != $CI_DEFAULT_BRANCH'
              when: on_success

            # forks: other web/api/scheduled pipelines
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE =~ /(web|api|schedule)/ && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE =~ /(web|api|schedule)/'
              when: on_success

            # upstream+forks: merge requests targeting the default branch, with CI changes
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH && $JOB_OPTIONAL'
              changes:
                - {cidir}/gitlab/container-templates.yml
                - {cidir}/containers/$NAME.Dockerfile
              when: manual
              allow_failure: true
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH'
              changes:
                - {cidir}/gitlab/container-templates.yml
                - {cidir}/containers/$NAME.Dockerfile
              when: on_success

            # upstream+forks: merge requests targeting non-default branches
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME != $CI_DEFAULT_BRANCH && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME != $CI_DEFAULT_BRANCH'
              when: on_success

            # upstream+forks: that's all folks
            - when: never
        """)


def native_build_template(project, cidir):
    return _build_template(".gitlab_native_build_job",
                           "ci-$NAME",
                           project,
                           cidir)


def cross_build_template(project, cidir):
    return _build_template(".gitlab_cross_build_job",
                           "ci-$NAME-cross-$CROSS",
                           project,
                           cidir)


def cirrus_template(cidir):
    return textwrap.dedent(
        f"""
        .cirrus_build_job:
          stage: builds
          image: registry.gitlab.com/libvirt/libvirt-ci/cirrus-run:latest
          interruptible: true
          needs: []
          script:
            - source {cidir}/cirrus/$NAME.vars
            - sed -e "s|[@]CI_REPOSITORY_URL@|$CI_REPOSITORY_URL|g"
                  -e "s|[@]CI_COMMIT_REF_NAME@|$CI_COMMIT_REF_NAME|g"
                  -e "s|[@]CI_COMMIT_SHA@|$CI_COMMIT_SHA|g"
                  -e "s|[@]CIRRUS_VM_INSTANCE_TYPE@|$CIRRUS_VM_INSTANCE_TYPE|g"
                  -e "s|[@]CIRRUS_VM_IMAGE_SELECTOR@|$CIRRUS_VM_IMAGE_SELECTOR|g"
                  -e "s|[@]CIRRUS_VM_IMAGE_NAME@|$CIRRUS_VM_IMAGE_NAME|g"
                  -e "s|[@]UPDATE_COMMAND@|$UPDATE_COMMAND|g"
                  -e "s|[@]UPGRADE_COMMAND@|$UPGRADE_COMMAND|g"
                  -e "s|[@]INSTALL_COMMAND@|$INSTALL_COMMAND|g"
                  -e "s|[@]PATH@|$PATH_EXTRA${{PATH_EXTRA:+:}}\\$PATH|g"
                  -e "s|[@]PKG_CONFIG_PATH@|$PKG_CONFIG_PATH|g"
                  -e "s|[@]PKGS@|$PKGS|g"
                  -e "s|[@]MAKE@|$MAKE|g"
                  -e "s|[@]PYTHON@|$PYTHON|g"
                  -e "s|[@]PIP3@|$PIP3|g"
                  -e "s|[@]PYPI_PKGS@|$PYPI_PKGS|g"
                  -e "s|[@]XML_CATALOG_FILES@|$XML_CATALOG_FILES|g"
              <{cidir}/cirrus/build.yml >{cidir}/cirrus/$NAME.yml
            - cat {cidir}/cirrus/$NAME.yml
            - cirrus-run -v --show-build-log always {cidir}/cirrus/$NAME.yml
          rules:
            # upstream+forks: Can't run unless Cirrus is configured
            - if: '$CIRRUS_GITHUB_REPO == null || $CIRRUS_API_TOKEN == null'
              when: never

            # upstream: pushes to branches
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE == $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push"'
              when: on_success

            # forks: pushes to branches with pipeline requested (including pipeline in upstream environment)
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE'
              when: on_success
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE_UPSTREAM_ENV && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $RUN_PIPELINE_UPSTREAM_ENV'
              when: on_success

            # upstream+forks: Run pipelines on MR, web, api & scheduled
            - if: '$CI_PIPELINE_SOURCE =~ /(web|api|schedule|merge_request_event)/ && $JOB_OPTIONAL'
              when: manual
              allow_failure: true
            - if: '$CI_PIPELINE_SOURCE =~ /(web|api|schedule|merge_request_event)/'
              when: on_success

            # upstream+forks: that's all folks
            - when: never
        """)


def check_dco_job():
    jobvars = {
        "GIT_DEPTH": "1000",
    }
    return textwrap.dedent(
        """
        check-dco:
          stage: sanity_checks
          needs: []
          image: registry.gitlab.com/libvirt/libvirt-ci/check-dco:latest
          interruptible: true
          script:
            - /check-dco "$RUN_UPSTREAM_NAMESPACE"
          rules:
            # upstream+forks: Run pipelines on MR
            - if: '$CI_PIPELINE_SOURCE =~ "merge_request_event"'
              when: on_success

            # forks: pushes to branches with pipeline requested (including upstream env pipelines)
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH && $RUN_PIPELINE'
              when: on_success
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH && $RUN_PIPELINE_UPSTREAM_ENV'
              when: on_success

            # upstream+forks: that's all folks
            - when: never
        """) + format_variables(jobvars)


def code_fmt_template():
    return textwrap.dedent(
        """
        .code_format:
          stage: sanity_checks
          image: registry.gitlab.com/libvirt/libvirt-ci/$NAME:latest
          interruptible: true
          needs: []
          script:
            - /$NAME
          rules:
            # upstream+forks: Run pipelines on MR, web, api & scheduled
            - if: '$CI_PIPELINE_SOURCE =~ /(web|api|schedule|merge_request_event)/'
              when: on_success

            # forks: pushes to branches with pipeline requested (including upstream env pipelines)
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH && $RUN_PIPELINE'
              when: on_success
            - if: '$CI_PROJECT_NAMESPACE != $RUN_UPSTREAM_NAMESPACE && $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH && $RUN_PIPELINE_UPSTREAM_ENV'
              when: on_success

            # upstream+forks: that's all folks
            - when: never
          artifacts:
            paths:
              - $NAME.$EXT
            expire_in: 1 week
            when: on_failure
        """)


def cargo_fmt_job():
    jobvars = {
        "NAME": "cargo-fmt",
        "EXT": "txt"
    }
    return textwrap.dedent(
        """
        cargo-fmt:
          extends: .code_format
        """) + format_variables(jobvars)


def go_fmt_job():
    jobvars = {
        "NAME": "go-fmt",
        "EXT": "patch"
    }
    return textwrap.dedent(
        """
        go-fmt:
          extends: .code_format
        """) + format_variables(jobvars)


def clang_format_job():
    jobvars = {
        "NAME": "clang-format",
        "EXT": "patch"
    }
    return textwrap.dedent(
        """
        clang-format:
          extends: .code_format
        """) + format_variables(jobvars)


def black_job():
    jobvars = {
        "NAME": "black",
        "EXT": "txt"
    }
    return textwrap.dedent(
        """
        black:
          extends: .code_format
        """) + format_variables(jobvars)


def flake8_job():
    jobvars = {
        "NAME": "flake8",
        "EXT": "txt"
    }
    return textwrap.dedent(
        """
        flake8:
          extends: .code_format
        """) + format_variables(jobvars)


def _container_job(target, arch, image, allow_failure, optional):
    allow_failure = str(allow_failure).lower()
    jobvars = {
        "NAME": image,
    }
    if optional:
        jobvars["JOB_OPTIONAL"] = "1"

    return textwrap.dedent(
        f"""
        {arch}-{target}-container:
          extends: .container_job
          allow_failure: {allow_failure}
        """) + format_variables(jobvars)


def native_container_job(target, allow_failure, optional):
    return _container_job(target,
                          "x86_64",
                          f"{target}",
                          allow_failure,
                          optional)


def cross_container_job(target, arch, allow_failure, optional):
    return _container_job(target,
                          arch,
                          f"{target}-cross-{arch}",
                          allow_failure,
                          optional)


def format_artifacts(artifacts):
    if artifacts is None:
        return ""

    expire_in = artifacts["expire_in"]
    paths = "\n".join(["      - " + p for p in artifacts["paths"]])

    section = textwrap.indent(textwrap.dedent(f"""
            artifacts:
              expire_in: {expire_in}
              paths:
           """), "  ") + paths + "\n"
    return section[1:]


def merge_vars(system, user):
    for key in user.keys():
        if key in system:
            raise ValueError(
                f"""Attempt to override system variable '{key}' in manifest""")
    return {**user, **system}


def _build_job(target, image, arch, suffix, variables,
               template, allow_failure, artifacts):
    allow_failure = str(allow_failure).lower()

    prebuilt = textwrap.dedent(
        f"""
        {arch}-{target}{suffix}-prebuilt-env:
          extends: {template}_prebuilt_env
          needs:
            - job: {arch}-{target}-container
              optional: true
          allow_failure: {allow_failure}
        """) + format_variables(variables) + format_artifacts(artifacts)

    variables["IMAGE"] = image

    local = textwrap.dedent(
        f"""
        {arch}-{target}{suffix}-local-env:
          extends: {template}_local_env
          needs: []
          allow_failure: {allow_failure}
        """) + format_variables(variables) + format_artifacts(artifacts)

    return prebuilt + local


def native_build_job(target, image, suffix, variables, template,
                     allow_failure, optional, artifacts):
    jobvars = merge_vars({
        "NAME": target,
    }, variables)
    if optional:
        jobvars["JOB_OPTIONAL"] = "1"

    return _build_job(target,
                      image,
                      "x86_64",
                      suffix,
                      jobvars,
                      template,
                      allow_failure,
                      artifacts)


def cross_build_job(target, image, arch, suffix, variables, template,
                    allow_failure, optional, artifacts):
    jobvars = merge_vars({
        "NAME": target,
        "CROSS": arch
    }, variables)
    if optional:
        jobvars["JOB_OPTIONAL"] = "1"

    return _build_job(target,
                      image,
                      arch,
                      suffix,
                      jobvars,
                      template,
                      allow_failure,
                      artifacts)


def cirrus_build_job(target, instance_type, image_selector, image_name, arch,
                     pkg_cmd, suffix, variables, allow_failure, optional):
    if pkg_cmd == "brew":
        install_cmd = "brew install"
        upgrade_cmd = "brew upgrade"
        update_cmd = "brew update"
    elif pkg_cmd == "pkg":
        install_cmd = "pkg install -y"
        upgrade_cmd = "pkg upgrade -y"
        update_cmd = "pkg update"
    else:
        raise ValueError(f"Unknown package command {pkg_cmd}")
    allow_failure = str(allow_failure).lower()
    jobvars = merge_vars({
        "NAME": target,
        "CIRRUS_VM_INSTANCE_TYPE": instance_type,
        "CIRRUS_VM_IMAGE_SELECTOR": image_selector,
        "CIRRUS_VM_IMAGE_NAME": image_name,
        "UPDATE_COMMAND": update_cmd,
        "UPGRADE_COMMAND": upgrade_cmd,
        "INSTALL_COMMAND": install_cmd,
    }, variables)
    if optional:
        jobvars["JOB_OPTIONAL"] = "1"

    return textwrap.dedent(
        f"""
        {arch}-{target}{suffix}:
          extends: .cirrus_build_job
          needs: []
          allow_failure: {allow_failure}
        """) + format_variables(jobvars)
