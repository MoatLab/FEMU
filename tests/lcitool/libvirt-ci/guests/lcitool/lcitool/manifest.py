# manifest.py - controls generation of all CI resources
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import yaml
from pathlib import Path

from lcitool.formatters import DockerfileFormatter, ShellVariablesFormatter
from lcitool.inventory import Inventory
from lcitool import gitlab
from lcitool import util


class Manifest:

    def __init__(self, configfp, quiet=False, cidir=Path("ci"), basedir=None):
        self.configpath = configfp.name
        self.values = yaml.safe_load(configfp)
        self.quiet = quiet
        self.cidir = cidir
        if basedir is None:
            self.outdir = cidir
        else:
            self.outdir = Path(basedir, cidir)

    # Fully expand any shorthand / syntax sugar in the config
    # so that later stages have a consistent view of the
    # config
    def _normalize(self):
        if "projects" not in self.values:
            raise Exception("No project list defined")

        projects = self.values["projects"]
        if type(projects) != list:
            raise Exception("projects must be a list")
        if len(projects) < 1:
            raise Exception("at least one project must be listed")

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
                raise Exception("gitlab namespace is required")
            if "project" not in gitlabinfo:
                raise Exception("gitlab project is required")

        gitlabinfo.setdefault("jobs", {})
        gitlabinfo.setdefault("templates", {})

        jobinfo = gitlabinfo["jobs"]
        jobinfo.setdefault("check-dco", True)
        jobinfo.setdefault("cargo-fmt", False)
        jobinfo.setdefault("go-fmt", False)
        jobinfo.setdefault("clang-fmt", False)

        templateinfo = gitlabinfo["templates"]
        templateinfo.setdefault("native-build", ".native_build_job")
        templateinfo.setdefault("cross-build", ".cross_build_job")

        targets = self.values.get("targets", {})
        if targets is None:
            targets = self.values["targets"] = {}
        have_containers = False
        have_cirrus = False
        inventory = Inventory()
        for target, targetinfo in targets.items():
            if type(targetinfo) == str:
                targets[target] = {"jobs": [{"arch": targetinfo}]}
                targetinfo = targets[target]
            targetinfo.setdefault("enabled", True)
            targetinfo.setdefault("projects", self.values["projects"])

            jobsinfo = targetinfo["jobs"]

            try:
                facts = inventory.target_facts[target]
            except KeyError:
                raise Exception(f"Invalid target '{target}'")

            targetinfo["containers"] = "containers" in facts
            if targetinfo["containers"]:
                have_containers = True
            targetinfo["cirrus"] = "cirrus" in facts
            if targetinfo["cirrus"]:
                have_cirrus = True

            done = {}
            for idx, jobinfo in enumerate(jobsinfo):
                if "arch" not in jobinfo:
                    raise Exception(f"target {target} job {idx} missing arch")
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
                if arch == "x86_64":
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
                        raise Exception(f"target {target} duplicate arch {arch} missing suffix")
                done[arch] = True

                if arch != "x86_64" and "cirrus" in facts:
                    raise Exception(f"target {target} does not support non-x86-64 architecture")

        if not have_containers:
            gitlabinfo["containers"] = False
        if not have_containers and not have_cirrus:
            gitlabinfo["builds"] = False
        gitlabinfo["cirrus"] = have_cirrus

    def generate(self, dryrun=False):
        self._normalize()

        if self.values["containers"]["enabled"]:
            generated = self._generate_containers(dryrun)
            self._clean_containers(generated, dryrun)

        if self.values["cirrus"]["enabled"]:
            generated = self._generate_cirrus(dryrun)
            self._clean_cirrus(generated, dryrun)

        if self.values["gitlab"]["enabled"]:
            self._generate_gitlab(dryrun)

    def _generate_formatter(self, dryrun, subdir, suffix, formatter, targettype):
        outdir = Path(self.outdir, subdir)
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
                    payload = formatter.format(target,
                                               wantprojects,
                                               arch)
                    util.atomic_write(filename, header + payload + "\n")

        return generated

    def _generate_containers(self, dryrun):
        formatter = DockerfileFormatter()
        return self._generate_formatter(dryrun,
                                        "containers", "Dockerfile",
                                        formatter, "containers")

    def _generate_cirrus(self, dryrun):
        formatter = ShellVariablesFormatter()
        return self._generate_formatter(dryrun,
                                        "cirrus", "vars",
                                        formatter, "cirrus")

    def _clean_files(self, generated, dryrun, subdir, suffix):
        outdir = Path(self.outdir, subdir)
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

    def _generate_gitlab(self, dryrun):
        if not dryrun:
            self.outdir.mkdir(parents=True, exist_ok=True)

        gitlabfile = Path(self.outdir, "gitlab.yml")

        gitlabinfo = self.values["gitlab"]
        namespace = gitlabinfo["namespace"]
        project = gitlabinfo["project"]
        jobinfo = gitlabinfo["jobs"]

        gitlabcontent = []
        if gitlabinfo["containers"]:
            gitlabcontent.append(gitlab.container_template(namespace, project, self.cidir))
        if gitlabinfo["builds"]:
            gitlabcontent.append(gitlab.native_build_template())
            gitlabcontent.append(gitlab.cross_build_template())
        if gitlabinfo["cirrus"]:
            gitlabcontent.append(gitlab.cirrus_template(self.cidir))

        if jobinfo["check-dco"]:
            gitlabcontent.append(gitlab.check_dco_job(namespace))
        if jobinfo["cargo-fmt"]:
            gitlabcontent.append(gitlab.cargo_fmt_job())
        if jobinfo["go-fmt"]:
            gitlabcontent.append(gitlab.go_fmt_job())
        if jobinfo["clang-fmt"]:
            gitlabcontent.append(gitlab.clang_fmt_job())

        if gitlabinfo["containers"]:
            gitlabcontent.extend(self._generate_gitlab_native_container_jobs())
            gitlabcontent.extend(self._generate_gitlab_cross_container_jobs())
        if gitlabinfo["builds"]:
            gitlabcontent.extend(self._generate_gitlab_native_build_jobs())
            gitlabcontent.extend(self._generate_gitlab_cross_build_jobs())
            gitlabcontent.extend(self._generate_gitlab_cirrus_build_jobs())

        if len(gitlabcontent) == 0:
            if not self.quiet:
                print(f"Deleting {gitlabfile}")
            gitlabfile.unlink(missing_ok=True)
            return

        if not self.quiet:
            print(f"Generating {gitlabfile}")
        header = util.generate_file_header(["manifest", self.configpath])

        lines = header + "\n".join(gitlabcontent)
        if not dryrun:
            util.atomic_write(gitlabfile, lines)

    def _generate_gitlab_container_jobs(self, cross):
        jobs = []
        for target, targetinfo in self.values["targets"].items():
            if not targetinfo["enabled"]:
                continue
            if not targetinfo["containers"]:
                continue

            done = {}
            for jobinfo in targetinfo["jobs"]:
                if not jobinfo["enabled"]:
                    continue
                if jobinfo["cross-build"] != cross:
                    continue

                arch = jobinfo["arch"]
                if arch in done:
                    continue
                done[arch] = True

                allow_failure = jobinfo["allow-failure"]
                if cross:
                    containerbuildjob = gitlab.cross_container_job(
                        target, arch, allow_failure)
                else:
                    containerbuildjob = gitlab.native_container_job(
                        target, allow_failure)
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
        inventory = Inventory()
        for target, targetinfo in self.values["targets"].items():
            if not targetinfo["enabled"]:
                continue
            if not targetinfo[targettype]:
                continue

            try:
                facts = inventory.target_facts[target]
            except KeyError:
                raise Exception(f"Invalid target '{target}'")

            for jobinfo in targetinfo["jobs"]:
                if not jobinfo["enabled"]:
                    continue
                if not jobinfo["builds"]:
                    continue
                if jobinfo["cross-build"] != cross:
                    continue

                jobs.append(jobfunc(target, facts, jobinfo))
        return jobs

    def _generate_gitlab_native_build_jobs(self):
        def jobfunc(target, facts, jobinfo):
            return gitlab.native_build_job(
                target,
                jobinfo["suffix"],
                jobinfo["variables"],
                jobinfo["template"],
                jobinfo["allow-failure"],
                jobinfo["artifacts"])

        jobs = self._generate_build_jobs("containers", False, jobfunc)
        if len(jobs) > 0:
            jobs = ["\n# Native build jobs"] + jobs
        return jobs

    def _generate_gitlab_cross_build_jobs(self):
        def jobfunc(target, facts, jobinfo):
            return gitlab.cross_build_job(
                target,
                jobinfo["arch"],
                jobinfo["suffix"],
                jobinfo["variables"],
                jobinfo["template"],
                jobinfo["allow-failure"],
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
                facts["packaging"]["command"],
                jobinfo["suffix"],
                jobinfo["variables"],
                jobinfo["allow-failure"])

        jobs = self._generate_build_jobs("cirrus", False, jobfunc)
        if len(jobs) > 0:
            jobs = ["\n# Native cirrus build jobs"] + jobs
        return jobs
