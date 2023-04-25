# manifest.py - controls generation of all CI resources
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import yaml
from pathlib import Path

from lcitool.formatters import DockerfileFormatter, ShellVariablesFormatter, ShellBuildEnvFormatter
from lcitool import gitlab, util, LcitoolError
from lcitool.targets import BuildTarget

log = logging.getLogger(__name__)


class ManifestError(LcitoolError):
    """Global exception type for the manifest module."""

    def __init__(self, message):
        super().__init__(message, "Manifest")


class Manifest:

    def __init__(self, targets, packages, projects, configfp, quiet=False, cidir=Path("ci"), basedir=None):
        self._targets = targets
        self._packages = packages
        self._projects = projects
        self.configpath = configfp.name
        self.values = yaml.safe_load(configfp)
        self.quiet = quiet
        self.cidir = cidir
        if basedir is None:
            self.basedir = Path()
        else:
            self.basedir = basedir

    # Fully expand any shorthand / syntax sugar in the config
    # so that later stages have a consistent view of the
    # config
    def _normalize(self):
        if "projects" not in self.values:
            raise ValueError("No project list defined")

        projects = self.values["projects"]
        if type(projects) != list:
            raise ValueError("projects must be a list")
        if len(projects) < 1:
            raise ValueError("at least one project must be listed")

        if "containers" not in self.values:
            self.values["containers"] = {}
        containerinfo = self.values["containers"]
        containerinfo.setdefault("enabled", True)

        if "cirrus" not in self.values:
            self.values["cirrus"] = {}
        cirrusinfo = self.values["cirrus"]
        cirrusinfo.setdefault("enabled", True)

        if "gitlab" not in self.values:
            self.values["gitlab"] = {}
        gitlabinfo = self.values["gitlab"]
        gitlabinfo.setdefault("enabled", True)
        gitlabinfo.setdefault("containers", True)
        gitlabinfo.setdefault("builds", True)

        if gitlabinfo["enabled"]:
            if "namespace" not in gitlabinfo:
                raise ValueError("gitlab namespace is required")
            if "project" not in gitlabinfo:
                raise ValueError("gitlab project is required")

        gitlabinfo.setdefault("jobs", {})
        gitlabinfo.setdefault("templates", {})

        jobinfo = gitlabinfo["jobs"]
        jobinfo.setdefault("check-dco", True)
        jobinfo.setdefault("cargo-fmt", False)
        jobinfo.setdefault("go-fmt", False)
        jobinfo.setdefault("clang-format", False)
        jobinfo.setdefault("black", False)
        jobinfo.setdefault("flake8", False)

        templateinfo = gitlabinfo["templates"]
        templateinfo.setdefault("native-build", ".native_build_job")
        templateinfo.setdefault("cross-build", ".cross_build_job")

        targets = self.values.get("targets", {})
        if targets is None:
            targets = self.values["targets"] = {}
        have_containers = False
        have_cirrus = False
        for target, targetinfo in targets.items():
            if type(targetinfo) == str:
                targets[target] = {"jobs": [{"arch": targetinfo}]}
                targetinfo = targets[target]
            targetinfo.setdefault("enabled", True)
            targetinfo.setdefault("projects", self.values["projects"])

            jobsinfo = targetinfo["jobs"]

            try:
                facts = self._targets.target_facts[target]
            except KeyError:
                raise ValueError(f"Invalid target '{target}'")

            targetinfo["containers"] = "containers" in facts
            if targetinfo["containers"]:
                have_containers = True
            targetinfo["cirrus"] = "cirrus" in facts
            if targetinfo["cirrus"]:
                have_cirrus = True

            done = {}
            for idx, jobinfo in enumerate(jobsinfo):
                if "arch" not in jobinfo:
                    raise ValueError(f"target {target} job {idx} missing arch")
                jobinfo.setdefault("enabled", True)
                jobinfo.setdefault("allow-failure", False)
                jobinfo.setdefault("artifacts", None)
                jobinfo.setdefault("variables", {})
                jobinfo.setdefault("suffix", "")
                jobinfo.setdefault("builds", gitlabinfo["builds"])

                artifacts = jobinfo["artifacts"]
                if artifacts is not None:
                    artifacts.setdefault("expire_in", "2 days")

                arch = jobinfo["arch"]
                if arch == "x86_64" or "cirrus" in facts:
                    jobinfo.setdefault("cross-build", False)
                else:
                    jobinfo.setdefault("cross-build", True)

                if targetinfo["containers"]:
                    if jobinfo["cross-build"]:
                        jobinfo.setdefault("template", templateinfo["cross-build"])
                    else:
                        jobinfo.setdefault("template", templateinfo["native-build"])

                if arch in done:
                    if jobinfo["suffix"] == "":
                        raise ValueError(f"target {target} duplicate arch {arch} missing suffix")
                done[arch] = True

                if "cirrus" in facts:
                    ciarch = facts["cirrus"]["arch"]
                    if arch != ciarch:
                        raise ValueError(f"target {target} only supports {ciarch} architecture")

        if not have_containers:
            gitlabinfo["containers"] = False
        if not have_containers and not have_cirrus:
            gitlabinfo["builds"] = False
        gitlabinfo["cirrus"] = have_cirrus

    def generate(self, dryrun=False):
        try:
            self._normalize()

            if self.values["containers"]["enabled"]:
                generated = self._generate_containers(dryrun)
                self._clean_containers(generated, dryrun)
                generated = self._generate_buildenv(dryrun)
                self._clean_buildenv(generated, dryrun)

            if self.values["cirrus"]["enabled"]:
                generated = self._generate_cirrus(dryrun)
                self._clean_cirrus(generated, dryrun)

            if self.values["gitlab"]["enabled"]:
                self._generate_gitlab(dryrun)
        except Exception as ex:
            log.debug("Failed to generate configuration")
            raise ManifestError(f"Failed to generate configuration: {ex}")

    def _generate_formatter(self, dryrun, subdir, suffix, formatter, targettype):
        outdir = Path(self.basedir, self.cidir, subdir)
        if not dryrun:
            outdir.mkdir(parents=True, exist_ok=True)

        generated = []
        for target, targetinfo in self.values["targets"].items():
            if not targetinfo["enabled"]:
                continue
            if not targetinfo[targettype]:
                continue

            wantprojects = targetinfo["projects"]

            for jobinfo in targetinfo["jobs"]:
                if not jobinfo["enabled"]:
                    continue

                arch = jobinfo["arch"]

                if jobinfo["cross-build"]:
                    filename = Path(outdir, f"{target}-cross-{arch}.{suffix}")
                else:
                    filename = Path(outdir, f"{target}.{suffix}")
                    arch = None

                if not self.quiet:
                    print(f"Generating {filename}")
                generated.append(filename)
                if not dryrun:
                    header = util.generate_file_header(["manifest",
                                                        self.configpath])
                    payload = formatter.format(BuildTarget(self._targets, self._packages, target, arch),
                                               wantprojects)
                    util.atomic_write(filename, header + payload + "\n")

        return generated

    def _generate_containers(self, dryrun):
        formatter = DockerfileFormatter(self._projects)
        return self._generate_formatter(dryrun,
                                        "containers", "Dockerfile",
                                        formatter, "containers")

    def _generate_cirrus(self, dryrun):
        formatter = ShellVariablesFormatter(self._projects)
        return self._generate_formatter(dryrun,
                                        "cirrus", "vars",
                                        formatter, "cirrus")

    def _generate_buildenv(self, dryrun):
        formatter = ShellBuildEnvFormatter(self._projects)
        return self._generate_formatter(dryrun,
                                        "buildenv", "sh",
                                        formatter, "containers")

    def _clean_files(self, generated, dryrun, subdir, suffix):
        outdir = Path(self.basedir, self.cidir, subdir)
        if not outdir.exists():
            return

        for filename in outdir.glob("*." + suffix):
            if filename not in generated:
                if not self.quiet:
                    print(f"Deleting {filename}")
                if not dryrun:
                    filename.unlink()

    def _clean_containers(self, generated, dryrun):
        self._clean_files(generated, dryrun, "containers", "Dockerfile")

    def _clean_cirrus(self, generated, dryrun):
        self._clean_files(generated, dryrun, "cirrus", "vars")

    def _clean_buildenv(self, generated, dryrun):
        self._clean_files(generated, dryrun, "buildenv", "sh")

    def _replace_file(self, content, path, dryrun):
        path = Path(self.basedir, path)
        if len(content) == 0:
            if not self.quiet:
                print(f"Deleting {path}")
            path.unlink(missing_ok=True)
            return

        if not self.quiet:
            print(f"Generating {path}")
        header = util.generate_file_header(["manifest", self.configpath])

        lines = header + "\n".join(content)
        lines = lines.strip() + "\n"
        if not dryrun:
            util.atomic_write(path, lines)

    def _generate_gitlab(self, dryrun):
        gitlabdir = Path(self.cidir, "gitlab")
        if not dryrun:
            Path(self.basedir, gitlabdir).mkdir(parents=True, exist_ok=True)

        have_native = False
        have_cross = False
        for target, targetinfo in self.values["targets"].items():
            if not targetinfo["enabled"] or not targetinfo["containers"]:
                continue

            for jobinfo in targetinfo["jobs"]:
                if not jobinfo["enabled"]:
                    continue
                if jobinfo["cross-build"]:
                    have_cross = True
                else:
                    have_native = True

        gitlabinfo = self.values["gitlab"]
        namespace = gitlabinfo["namespace"]
        project = gitlabinfo["project"]
        jobinfo = gitlabinfo["jobs"]

        includes = []
        if gitlabinfo["containers"]:
            path = Path(gitlabdir, "container-templates.yml")
            content = [gitlab.container_template(self.cidir)]
            self._replace_file(content, path, dryrun)
            if len(content) > 0:
                includes.append(path)

        path = Path(gitlabdir, "build-templates.yml")
        content = []
        if have_native:
            content.append(gitlab.native_build_template(project, self.cidir))
        if have_cross:
            content.append(gitlab.cross_build_template(project, self.cidir))
        if gitlabinfo["cirrus"]:
            content.append(gitlab.cirrus_template(self.cidir))
        self._replace_file(content, path, dryrun)
        if len(content) > 0:
            includes.append(path)

        fmtcontent = []
        if jobinfo["cargo-fmt"]:
            fmtcontent.append(gitlab.cargo_fmt_job())
        if jobinfo["go-fmt"]:
            fmtcontent.append(gitlab.go_fmt_job())
        if jobinfo["clang-format"]:
            fmtcontent.append(gitlab.clang_format_job())
        if jobinfo["black"]:
            fmtcontent.append(gitlab.black_job())
        if jobinfo["flake8"]:
            fmtcontent.append(gitlab.flake8_job())

        testcontent = []
        if jobinfo["check-dco"]:
            testcontent.append(gitlab.check_dco_job())
        if len(fmtcontent):
            testcontent.append(gitlab.code_fmt_template())
            testcontent.extend(fmtcontent)

        path = Path(gitlabdir, "sanity-checks.yml")
        self._replace_file(testcontent, path, dryrun)
        if len(testcontent) > 0:
            includes.append(path)

        if gitlabinfo["containers"]:
            path = Path(gitlabdir, "containers.yml")
            content = []
            content.extend(self._generate_gitlab_native_container_jobs())
            content.extend(self._generate_gitlab_cross_container_jobs())
            self._replace_file(content, path, dryrun)
            if len(content) > 0:
                includes.append(path)

        if gitlabinfo["builds"]:
            path = Path(gitlabdir, "builds.yml")
            content = []
            content.extend(self._generate_gitlab_native_build_jobs())
            content.extend(self._generate_gitlab_cross_build_jobs())
            content.extend(self._generate_gitlab_cirrus_build_jobs())
            self._replace_file(content, path, dryrun)
            if len(content) > 0:
                includes.append(path)

        path = Path(self.cidir, "gitlab.yml")
        content = [gitlab.docs(namespace),
                   gitlab.variables(namespace),
                   gitlab.workflow(),
                   gitlab.debug(),
                   gitlab.includes(includes)]
        self._replace_file(content, path, dryrun)

    def _generate_gitlab_container_jobs(self, cross):
        jobs = []
        for target, targetinfo in self.values["targets"].items():
            if not targetinfo["enabled"]:
                continue
            if not targetinfo["containers"]:
                continue

            done = {}
            for jobinfo in targetinfo["jobs"]:
                if not jobinfo["enabled"] or jobinfo["cross-build"] != cross:
                    continue

                arch = jobinfo["arch"]
                if arch in done:
                    continue
                done[arch] = True

                allow_failure = True
                optional = True
                for thatjobinfo in targetinfo["jobs"]:
                    if not thatjobinfo["enabled"]:
                        continue
                    if thatjobinfo["cross-build"] != cross:
                        continue
                    if thatjobinfo["arch"] != arch:
                        continue

                    if not thatjobinfo["allow-failure"]:
                        allow_failure = False

                    if thatjobinfo["builds"]:
                        optional = False

                if cross:
                    containerbuildjob = gitlab.cross_container_job(
                        target, arch, allow_failure, optional)
                else:
                    containerbuildjob = gitlab.native_container_job(
                        target, allow_failure, optional)
                jobs.append(containerbuildjob)
        return jobs

    def _generate_gitlab_native_container_jobs(self):
        jobs = self._generate_gitlab_container_jobs(False)
        if len(jobs) > 0:
            jobs = ["\n# Native container jobs"] + jobs
        return jobs

    def _generate_gitlab_cross_container_jobs(self):
        jobs = self._generate_gitlab_container_jobs(True)
        if len(jobs) > 0:
            jobs = ["\n\n# Cross container jobs"] + jobs
        return jobs

    def _generate_build_jobs(self, targettype, cross, jobfunc):
        jobs = []
        for target, targetinfo in self.values["targets"].items():
            if not targetinfo["enabled"]:
                continue
            if not targetinfo[targettype]:
                continue

            try:
                facts = self._targets.target_facts[target]
            except KeyError:
                raise ManifestError(f"Invalid target '{target}'")

            for jobinfo in targetinfo["jobs"]:
                if not jobinfo["enabled"]:
                    continue
                if jobinfo["cross-build"] != cross:
                    continue

                jobs.append(jobfunc(target, facts, jobinfo))
        return jobs

    def _generate_gitlab_native_build_jobs(self):
        def jobfunc(target, facts, jobinfo):
            return gitlab.native_build_job(
                target,
                facts["containers"]["base"],
                jobinfo["suffix"],
                jobinfo["variables"],
                jobinfo["template"],
                jobinfo["allow-failure"],
                not jobinfo["builds"],
                jobinfo["artifacts"])

        jobs = self._generate_build_jobs("containers", False, jobfunc)
        if len(jobs) > 0:
            jobs = ["\n# Native build jobs"] + jobs
        return jobs

    def _generate_gitlab_cross_build_jobs(self):
        def jobfunc(target, facts, jobinfo):
            return gitlab.cross_build_job(
                target,
                facts["containers"]["base"],
                jobinfo["arch"],
                jobinfo["suffix"],
                jobinfo["variables"],
                jobinfo["template"],
                jobinfo["allow-failure"],
                not jobinfo["builds"],
                jobinfo["artifacts"])

        jobs = self._generate_build_jobs("containers", True, jobfunc)
        if len(jobs) > 0:
            jobs = ["\n\n# Cross build jobs"] + jobs
        return jobs

    def _generate_gitlab_cirrus_build_jobs(self):
        def jobfunc(target, facts, jobinfo):
            return gitlab.cirrus_build_job(
                target,
                facts["cirrus"]["instance_type"],
                facts["cirrus"]["image_selector"],
                facts["cirrus"]["image_name"],
                facts["cirrus"]["arch"],
                facts["packaging"]["command"],
                jobinfo["suffix"],
                jobinfo["variables"],
                jobinfo["allow-failure"],
                not jobinfo["builds"])

        jobs = self._generate_build_jobs("cirrus", False, jobfunc)
        if len(jobs) > 0:
            jobs = ["\n# Native cirrus build jobs"] + jobs
        return jobs
