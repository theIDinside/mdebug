from os import path, makedirs, listdir, environ

from .base import Command, Argument, presets, runCommand
from tooling.metadata import BuildMetadata
import zipfile, tarfile
from pathlib import Path
from shutil import rmtree, copy2


def download(url, destination):
    runCommand(["wget", "-q", "-O", str(destination), url])


def getZipTopLevelDirectories(zipFile: zipfile.ZipFile) -> list[str]:
    result = set()
    for member in zipFile.namelist():
        result.add(member.split("/")[0])
    return list(result)


def getTarTopLevelDirectories(tarFile: tarfile.TarFile) -> list[str]:
    result = set()
    for member in tarFile.getmembers():
        result.add(member.name.split("/")[0])
    return list(result)


def decompress(archivePath, name):
    """
    Extracts a zip or tar archive into a new directory called `name`.

    :param archive_path: Path to the archive (.zip, .tar, .tar.gz, .tgz)
    :param name: Name of the directory where contents will be extracted
    """
    archivePath = Path(archivePath)
    targetDirectory = Path(name)
    targetDirectory.mkdir(parents=True, exist_ok=True)

    if archivePath.suffix == ".zip":
        with zipfile.ZipFile(archivePath, "r") as zf:
            topLevelDirectories = getZipTopLevelDirectories(zipFile=zf)
            hasOneTopLevelDir = len(topLevelDirectories) == 1
            for member in zf.namelist():
                # If the archive had multiple top-level directories and files
                # we don't remove the prefix. We only remove the prefix for the archive
                # that contains a top-level directory, as this directory is just noise.
                adjustedMemberPath = targetDirectory / (
                    member.removeprefix(f"{topLevelDirectories[0]}/")
                    if hasOneTopLevelDir
                    else member
                )
                # skip creating the top level
                if member == topLevelDirectories[0]:
                    continue
                if member.endswith("/"):
                    # Directory
                    adjustedMemberPath.mkdir(parents=True, exist_ok=True)
                else:
                    # File
                    adjustedMemberPath.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as source, open(
                        adjustedMemberPath, "wb"
                    ) as dest:
                        dest.write(source.read())
    elif archivePath.suffix in (".tar", ".gz", ".tgz") or archivePath.name.endswith(
        (".tar.gz", ".tar", ".tar.xz")
    ):
        with tarfile.open(archivePath, "r:*") as tf:
            topLevelDirectories = getTarTopLevelDirectories(tarFile=tf)
            hasOneTopLevelDir = len(topLevelDirectories) == 1
            for member in tf.getmembers():
                adjustedMemberPath = targetDirectory / (
                    member.name.removeprefix(f"{topLevelDirectories[0]}/")
                    if hasOneTopLevelDir
                    else member.name
                )
                if member.name == topLevelDirectories[0]:
                    continue
                if member.isdir():
                    adjustedMemberPath.mkdir(parents=True, exist_ok=True)
                else:
                    adjustedMemberPath.parent.mkdir(parents=True, exist_ok=True)
                    with tf.extractfile(member) as source, open(
                        adjustedMemberPath, "wb"
                    ) as dest:
                        dest.write(source.read())
    else:
        raise ValueError(
            "Unsupported archive format. Only .zip, .tar, .tar.gz, .tgz are supported."
        )

    print(f"Extracted {archivePath} into {targetDirectory}")


class Dependency:
    def __init__(self, declaration, file):
        self.declaration: DependencyDeclaration = declaration
        self.file: str = file
        self.doConfigure = (
            lambda buildMetadata, extractedTo: self.declaration.configureStep(
                self, buildMetadata, extractedTo
            )
        )

    def extract(self, extractTo: str):
        print(f"Decompress file {self.file} to {extractTo}")
        if not Path(extractTo).exists():
            decompress(self.file, extractTo)
        else:
            print(
                f"Directory {extractTo} exists already, assuming that archive already has been extracted."
            )


def defaultConfigure(dependency: Dependency, buildMetaData: BuildMetadata, extractedTo):
    pass


def configureQuickJs(
    dependency: Dependency, buildMetaData: BuildMetadata, extractedTo: str
):
    outputFile = f"{extractedTo}/CMakeLists.txt"
    print(
        f"copying {buildMetaData.getProjectPath("cmake/QuickJs.cmake")} to {outputFile}"
    )
    copy2(src=buildMetaData.getProjectPath("cmake/QuickJs.cmake"), dst=outputFile)


class DependencyDeclaration:
    def __init__(
        self,
        lib,
        version,
        urlTemplate: str,
        archiveKind,
        DependencyType=Dependency,
        configureStep=defaultConfigure,
        localName=None,
    ):
        """`lib` represents the library name. `localName` is an optional rename"""
        self.lib = lib
        self.version = version
        self.localName = localName
        self.downloadUrl = urlTemplate.replace("$(VERSION)", self.version)
        self.archiveKind = archiveKind
        self.producedDependencyType: Dependency = DependencyType
        self.configureStep = configureStep

    def getDependencyFileName(self):
        return f"{self.lib}.{self.archiveKind}"

    def to_json(self):
        if self.localName:
            return {"name": self.localName, "version": self.version}
        return {"version": self.version}

    def download(self, directory: str) -> Dependency | None:
        print(f"Downloading dependency '{self.lib}' to {directory}")
        try:
            file = path.join(directory, self.getDependencyFileName())
            if path.exists(file):
                print(f"File {file} already downloaded, skipping.")
                return self.producedDependencyType(self, file)
            download(
                url=self.downloadUrl,
                destination=file,
            )
            return self.producedDependencyType(self, file)
        except Exception as e:
            print(f"Download of dependency {self.lib} failed: {e}")
            return None


class SetupProjectCommand(Command):
    projectDependencies = [
        DependencyDeclaration(
            lib="quickjs",
            version="2025-04-26",
            urlTemplate="https://bellard.org/quickjs/quickjs-$(VERSION).tar.xz",
            archiveKind="tar.xz",
            configureStep=configureQuickJs,
        ),
        DependencyDeclaration(
            lib="nlohmann_json",
            version="v3.11.2",
            urlTemplate="https://github.com/nlohmann/json/releases/download/$(VERSION)/json.tar.xz",
            archiveKind="tar.xz",
        ),
        DependencyDeclaration(
            lib="googletest",
            version="03597a01ee50ed33e9dfd640b249b4be3799d395",
            urlTemplate="https://github.com/google/googletest/archive/$(VERSION).zip",
            archiveKind="zip",
        ),
        DependencyDeclaration(
            lib="zydis",
            version="v4.0.0",
            urlTemplate="https://github.com/zyantific/zydis/releases/download/$(VERSION)/zydis-amalgamated.tar.gz",
            archiveKind="tar.gz",
        ),
    ]

    description = "Setup project and download dependencies."
    useMessage = f"This command must be run to download & process the dependencies of the project. It will download the following dependencies:\n{"\n".join([f"    - {x.lib}" for x in projectDependencies])}"
    arguments = [
        Argument(
            name="Directory",
            description="Target directory to download the dependencies and extract them in. This should normally not be used, and is just used for testing purposes (so that it doesn't overwrite any current dependencies).",
            typeName="string",
            type_=str,
            required=False,
        )
    ]
    hasFixedArguments = True

    def __init__(self):
        super().__init__("dev-setup", commandInstance=self)

    def run(self, buildMetadata: BuildMetadata, args):
        downloadDirectory = (
            buildMetadata.getProjectPath("dependencies")
            if not args
            else buildMetadata.getProjectPath(args[0])
        )

        for declaration in SetupProjectCommand.projectDependencies:
            dependency = declaration.download(directory=downloadDirectory)
            if dependency is not None:
                try:
                    extractTo = path.join(
                        downloadDirectory,
                        (
                            dependency.declaration.lib
                            if dependency.declaration.localName is None
                            else dependency.declaration.localName
                        ),
                    )
                    dependency.extract(extractTo=extractTo)
                    dependency.doConfigure(
                        buildMetadata=buildMetadata, extractedTo=extractTo
                    )
                except Exception as e:
                    print(f"extracting file {dependency.file} failed: {e}")
            else:
                print(f"Dependency {declaration.lib} was not configured")


class ConfigureBuildRootCommand(Command):
    description = "Configure root build directory for presets to be placed in."
    useMessage = "Configure where the build system shall put it's root build directory. Under this directory, there will be one directory for each configured build type."
    arguments = [
        Argument(
            name="Directory",
            description="The path to where the root build directory shall be configured for. If the directory does not exist, this will create it.",
            typeName="string",
            type_=str,
            required=True,
        )
    ]

    def __init__(self):
        super().__init__("configure-buildroot", commandInstance=self)

    def run(self, buildMetadata: BuildMetadata, args):
        rootBuildDir = args[0]
        canonical = path.abspath(rootBuildDir)
        if not path.exists(canonical):
            makedirs(canonical)

        buildMetadata.configureRootDirectory(canonical)


class ConfigureCommand(Command):
    description = "Run cmake configure for a preset"
    useMessage = "Configure a CMake build preset and place the build directory in the configured root build directory, with the preset name append to the path. See 'build.py help setup'. If no root build directory is configured, ./build will be used."
    arguments = [
        Argument(
            name="Build preset",
            description=f"Build preset to configure, one of  [{", ".join(presets)}]",
            typeName="string",
            type_=str,
            required=True,
        )
    ]

    def __init__(self):
        super().__init__("configure", commandInstance=self)

    def validate(self, buildMetadata: BuildMetadata, args) -> list:
        return args

    def run(self, buildMetadata: BuildMetadata, args):
        buildPreset = args[0]
        if buildPreset not in presets:
            raise ValueError(
                f"Invalid build type. Must be one of: {', '.join(presets)}."
            )

        rootBuildDirectory = buildMetadata.getBuildRoot()
        buildDirectory = path.join(rootBuildDirectory, buildPreset.lower())

        if not path.exists(buildDirectory):
            makedirs(buildDirectory)

        cmakeCommand = [
            "cmake",
            f"--preset {buildPreset}",
            f"-B {buildDirectory}",
            f"-S {buildMetadata.getProjectPath()}",
        ]
        for arg in args[1:]:
            cmakeCommand.append(arg)

        runCommand(cmakeCommand, cwd=buildDirectory)
        buildMetadata.addConfigured(buildType=buildPreset)


class ListPresetsCommand(Command):
    description = "List the cmake presets of this project."
    useMessage = description
    arguments = []

    def __init__(self):
        super().__init__("list-presets", commandInstance=self)

    def run(self, buildMetadata: BuildMetadata, args):
        cmakeCommand = ["cmake", f"--list-presets"]
        runCommand(cmakeCommand)


SetupProjectCommand()
ConfigureBuildRootCommand()
ConfigureCommand()
ListPresetsCommand()
