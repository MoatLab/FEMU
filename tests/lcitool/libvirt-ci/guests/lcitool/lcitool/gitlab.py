# gitlab.py - helpers for generating CI rules from templates
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import textwrap


def container_template(namespace, project, cidir):
    return textwrap.dedent(
        f"""
        .container_job:
          image: docker:stable
          stage: containers
          needs: []
          services:
            - name: registry.gitlab.com/libvirt/libvirt-ci/docker-dind:master
              alias: docker
          before_script:
            - export TAG="$CI_REGISTRY_IMAGE/ci-$NAME:latest"
            - export COMMON_TAG="$CI_REGISTRY/{namespace}/{project}/ci-$NAME:latest"
            - docker info
            - docker login registry.gitlab.com -u "$CI_REGISTRY_USER" -p "$CI_REGISTRY_PASSWORD"
          script:
            - docker pull "$TAG" || docker pull "$COMMON_TAG" || true
            - docker build --cache-from "$TAG" --cache-from "$COMMON_TAG" --tag "$TAG" -f "{cidir}/containers/$NAME.Dockerfile" {cidir}/containers
            - docker push "$TAG"
          after_script:
            - docker logout
        """)


def native_build_template():
    return textwrap.dedent(
        """
        .gitlab_native_build_job:
          image: $CI_REGISTRY_IMAGE/ci-$NAME:latest
          stage: builds
        """)


def cross_build_template():
    return textwrap.dedent(
        """
        .gitlab_cross_build_job:
          image: $CI_REGISTRY_IMAGE/ci-$NAME-cross-$CROSS:latest
          stage: builds
        """)


def cirrus_template(cidir):
    return textwrap.dedent(
        f"""
        .cirrus_build_job:
          stage: builds
          image: registry.gitlab.com/libvirt/libvirt-ci/cirrus-run:master
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
            - if: "$CIRRUS_GITHUB_REPO && $CIRRUS_API_TOKEN"
        """)


def check_dco_job(namespace):
    return textwrap.dedent(
        f"""
        check-dco:
          stage: sanity_checks
          needs: []
          image: registry.gitlab.com/libvirt/libvirt-ci/check-dco:master
          script:
            - /check-dco {namespace}
          except:
            variables:
              - $CI_PROJECT_NAMESPACE == '{namespace}'
          variables:
            GIT_DEPTH: 1000
        """)


def cargo_fmt_job():
    return textwrap.dedent(
        """
        cargo-fmt:
          stage: sanity_checks
          image: registry.gitlab.com/libvirt/libvirt-ci/cargo-fmt:master
          needs: []
          script:
            - /cargo-fmt
          artifacts:
            paths:
              - cargo-fmt.patch
            expire_in: 1 week
            when: on_failure
        """)


def go_fmt_job():
    return textwrap.dedent(
        """
        go-fmt:
          stage: sanity_checks
          image: registry.gitlab.com/libvirt/libvirt-ci/go-fmt:master
          needs: []
          script:
            - /go-fmt
          artifacts:
            paths:
              - go-fmt.patch
            expire_in: 1 week
            when: on_failure
        """)


def native_container_job(target, allow_failure):
    allow_failure = str(allow_failure).lower()

    return textwrap.dedent(
        f"""
        x86_64-{target}-container:
          extends: .container_job
          allow_failure: {allow_failure}
          variables:
            NAME: {target}
        """)


def cross_container_job(target, arch, allow_failure):
    allow_failure = str(allow_failure).lower()

    return textwrap.dedent(
        f"""
        {arch}-{target}-container:
          extends: .container_job
          allow_failure: {allow_failure}
          variables:
            NAME: {target}-cross-{arch}
        """)


def format_variables(variables):
    job = []
    for key in sorted(variables.keys()):
        val = variables[key]
        job.append(f"    {key}: {val}")
    if len(job) > 0:
        return "  variables:\n" + "\n".join(job) + "\n"
    return ""


def format_artifacts(artifacts):
    if artifacts is None:
        return ""

    expire_in = artifacts["expire_in"]
    paths = "\n".join(["      - " + p for p in artifacts["paths"]])

    section = textwrap.indent(textwrap.dedent(f"""
            artifacts:
              expire_in: {expire_in}
              paths:
           """), "  ") + paths
    return section[1:]


def merge_vars(system, user):
    for key in user.keys():
        if key in system:
            raise Exception(
                f"""Attempt to override system variable '{key}' in manifest""")
    return {**user, **system}


def native_build_job(target, suffix, variables, template, allow_failure, artifacts):
    allow_failure = str(allow_failure).lower()
    jobvars = merge_vars({
        "NAME": target,
    }, variables)

    return textwrap.dedent(
        f"""
        x86_64-{target}{suffix}:
          extends: {template}
          needs:
            - x86_64-{target}-container
          allow_failure: {allow_failure}
        """) + format_variables(jobvars) + format_artifacts(artifacts)


def cross_build_job(target, arch, suffix, variables, template, allow_failure, artifacts):
    allow_failure = str(allow_failure).lower()
    jobvars = merge_vars({
        "NAME": target,
        "CROSS": arch
    }, variables)

    return textwrap.dedent(
        f"""
        {arch}-{target}{suffix}:
          extends: {template}
          needs:
            - {arch}-{target}-container
          allow_failure: {allow_failure}
        """) + format_variables(jobvars) + format_artifacts(artifacts)


def cirrus_build_job(target, instance_type, image_selector, image_name,
                     pkg_cmd, suffix, variables, allow_failure):
    if pkg_cmd == "brew":
        install_cmd = "brew install"
        upgrade_cmd = "brew upgrade"
        update_cmd = "brew update"
    elif pkg_cmd == "pkg":
        install_cmd = "pkg install -y"
        upgrade_cmd = "pkg upgrade -y"
        update_cmd = "pkg update"
    else:
        raise Exception(f"Unknown package command {pkg_cmd}")
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

    return textwrap.dedent(
        f"""
        x86_64-{target}{suffix}:
          extends: .cirrus_build_job
          needs: []
          allow_failure: {allow_failure}
        """) + format_variables(jobvars)
