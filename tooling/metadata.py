from os import path, makedirs
import json
from typing import Optional


class BuildMetadata:
    def __init__(self, projectDirectory, metadataFilePath):
        self.projectDirectory = projectDirectory
        self.metadataFilePath = metadataFilePath
        self.meta = {"configured": [], "selected": None}
        self.load()

    def load(self):
        """Load the persisted build system metadata"""
        if path.exists(self.metadataFilePath):
            with open(self.metadataFilePath, "r") as f:
                try:
                    self.meta = json.load(f)
                except json.JSONDecodeError:
                    print("Warning: Corrupt metadata file, resetting.")
                    self.meta = {"configured": [], "selected": None}
            self.cleanupMissingDirs()
        else:
            self.save()

    def save(self):
        with open(self.metadataFilePath, "w") as f:
            json.dump(self.meta, f, indent=4)

    def getProjectPath(self, subPath: Optional[str] = None):
        """Get the project root folder (the "cmake source folder" which is the top most directory in this repo.). If `subPath` is provided, it will be appended to the project directory path"""
        return (
            path.join(self.projectDirectory, subPath)
            if subPath is not None
            else self.projectDirectory
        )

    def configureRootDirectory(self, directory):
        # Default root build directory is ./build
        if directory is None:
            directory = path.join(self.projectDirectory, "build")
        canonical = path.abspath(directory)
        if not path.exists(canonical):
            makedirs(canonical)

        self.meta["buildRoot"] = canonical
        self.save()

    def getPresetBuildDir(self, preset) -> str:
        """Return the full path to `preset`."""
        if self.getBuildRoot() is None:
            raise Exception(
                "Build root directory has not been configured with the `setup` command."
            )
        return path.join(self.getBuildRoot(), preset)

    def getBuildRoot(self) -> str:
        return self.meta.get("buildRoot")

    def getConfigured(self):
        return self.meta.get("configured")

    def addConfigured(self, buildType):
        if buildType not in self.meta["configured"]:
            self.meta["configured"].append(buildType)
            self.setSelected(buildType)

    def removeConfigured(self, buildType):
        if buildType in self.meta["configured"]:
            self.meta["configured"].remove(buildType)
            self.save()

    def setSelected(self, buildType):
        """Set selected configuration. If `buildType`=`None`, we unset the selected configuration preset."""
        if buildType is None:
            if self.meta.get("selected") is not None:
                self.meta["selected"].remove()
                self.save()
        else:
            if buildType not in self.meta["configured"]:
                raise ValueError(f"Cannot select '{buildType}', it is not configured.")
            self.meta["selected"] = buildType
            self.save()

    def getSelected(self) -> str:
        if self.meta.get("selected") is None:
            raise ValueError(
                "No configuration has not been default selected using `mdbuild select <preset>`. `selected` also gets set to the newest configured preset."
            )
        return path.join(self.getBuildRoot(), self.meta["selected"])

    def cleanupMissingDirs(self):
        # Remove build types if their folders are missing
        existing = []
        for buildType in self.meta["configured"]:
            buildpath = path.join(self.getBuildRoot(), buildType.lower())
            if path.exists(buildpath):
                existing.append(buildType)
            else:
                print(
                    f"Warning: build/{buildType.lower()} missing, removing from metadata."
                )
        self.meta["configured"] = existing
        if self.meta["selected"] and self.meta["selected"] not in existing:
            print(
                f"Warning: selected build type '{self.meta['selected']}' no longer exists."
            )
            self.meta["selected"] = None
        self.save()
