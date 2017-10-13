#!/usr/bin/python
"""
Build package patches for libcare using toil[1] workflow framework.
The basic components are the following:

#. `Storage` class that works like a filesystem directory. Changes made to it
   are passed down the chain to all the jobs via `Promise` mechanism. The
   `Storage` class is also responsible for importing and exporting local files.

#. `FileFetcherJob` job that downloads specified files from the net and puts them in
   the storage. Supported are AWS S3, HTTP and FTP files. This is usually the
   first job.

#. `DoBuild` checks presence of the object in the Storage and runs
   `prebuildJob` chained with `uploadJob` and `buildJob` if the object is missing.
   Only `buildJob` is run otherwise.

   This is used to build missing parts such as an archive with the baseline
   source code called `prebuilt` which is listed as optional for the
   `FileFetcherJob` job.

#. `DockerScriptJob` that brings up a Docker container from the specified image
   and runs the Storage-suplied script with Storage content exposed into the
   `/data` directory.

#. `UploadJob` that uploads specified objects from the Storage.

#. `DoIfMissing` checks presence of the object in the Storage and runs
   specified job if it is missing.

#. `ChainJobs` is used to chain the jobs at the runtime.



All the updates to the Storage are carried from the children to the followOns
via `Promise` mechanism. The root job returns Storage from the last followOn,
this storage is then exported to a directory.

[1] https://toil.readthedocs.io/
"""

from __future__ import print_function

import boto3
import contextlib
import collections
import datetime
import dateutil
import errno
import logging
import os
import requests
import shutil
import tarfile
import tempfile
import time
import urlparse
import yaml

from toil.common import Toil
from toil.job import Job as toilJob
from toil.lib.docker import dockerCall, dockerCheckOutput, STOP, RM, FORGO


def myabspath(path_or_url, root=None):
    """Return absolute path for an url or path."""
    if '://' not in path_or_url or path_or_url.startswith('file://'):
        path_or_url = path_or_url.replace('file://', '')
        if (path_or_url[0] == '.' or '/' not in path_or_url) and root:
            path_or_url = os.path.join(root, path_or_url)
        path_or_url = os.path.abspath(path_or_url)
        return path_or_url
    return

FileInfo = collections.namedtuple('FileInfo', ('fileName', 'url', 'required'))

def parseFileInfo(fileInfo):
    """Parse fileInfo which is either an URL or a dictionary of form
    {"fileName": "url"}. When url is prefixed with '*' the file is optional.

    Samples:
    >>> parseFileInfo('http://kernel.org/index.html')
    ... "index.html", "http://kernel.org/index.html", True
    >>> parseFileInfo('*http://kernel.org/index.html')
    ... "index.html", "http://kernel.org/index.html", False
    >>> parseFileInfo({'foobar.html': '*http://kernel.org/index.html'})
    ... "foobar.html", "http://kernel.org/index.html", False
    """
    if isinstance(fileInfo, basestring):
        url = fileInfo
        fileName = os.path.basename(url)
    elif isinstance(fileInfo, dict):
        items = fileInfo.items()
        if len(items) != 1:
            raise ValueError("only one-entry dicts are allowed as fileInfo")
        fileName, url = items[0]

    required = True
    if url.startswith('*'):
        url = url.lstrip('*')
        required = False
    return FileInfo(fileName, url, required)


class WorkflowToFileStoreProxy(object):
    """
    Make File.copy and Directory.copy work with toil.common.Toil object.
    """
    def __init__(self, workflow):
        self.workflow = workflow

    def readGlobalFile(self, fileId):
        tmpfile = tempfile.mktemp()
        self.workflow.exportFile(fileId, 'file://' + tmpfile)
        return tmpfile

    def writeGlobalFile(self, path):
        return self.workflow.importFile('file:///' + path)

    def getLocalTempFile(self):
        return tempfile.mktemp()


class Storage(dict):
    """Keeps files organized for the workflow.

    This is a dictionary that associates fileName with a file object such
    as `File` or `Directory` class.

    Additional field `promised_updates` is used to keep track of updates
    resulting from `Promise`s of children.
    """
    def __init__(self, *args, **kwargs):
        self.promised_updates = []
        if args:
            self.promised_updates = list(args[0].promised_updates)

        super(Storage, self).__init__(*args, **kwargs)

    def update(self, other):
        """Update this Storage with files from another."""
        if isinstance(other, Storage):
            self.promised_updates.extend(other.promised_updates)

        if isinstance(other, dict):
            super(Storage, self).update(other)
        else:
            self.promised_updates.append(other)

    def __setstate__(self, state):
        """Unfold finished promised_updates."""
        self.promised_updates = []
        for promise in state['promised_updates']:
            self.update(promise)

    def __repr__(self):
        s = super(Storage, self).__repr__()
        return s + (" %r" % self.promised_updates)

    @contextlib.contextmanager
    def expose(self, rootDir=None):
        """Expose Storage to a directory and pick up changes from it."""
        if rootDir is None:
            rootDir = self.fileStore.getLocalTempDir()
        try:
            self.toDirectory(rootDir)
            yield rootDir
        finally:
            self.cleanupDirectory(rootDir)
        self.pickupDirectory(rootDir)

    def toDirectory(self, rootDir, export=False):
        """Copy Storage content to the specified directory."""
        for fileObj in self.values():
            if export and isinstance(fileObj, (ImportedFile, ImportedDirectory)):
                continue
            fileObj.copy(self.fileStore, rootDir)

    def pickupDirectory(self, directory):
        """Pick up content of the specified directory into the Storage."""
        files = ((name, os.path.join(directory, name))
                 for name in os.listdir(directory))
        return self.pickupFiles(self.fileStore, files)

    def cleanupDirectory(self, rootDir):
        """Remove storage files from the directory."""
        return
        for fileName in self:
            path = os.path.join(rootDir, fileName)

            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)

    def pickupFiles(self, fileStore, files):
        """Pick up listed files into the Storage."""
        for fileName, path in files:
            if fileName in self:
                continue

            if os.path.isdir(path):
                self[fileName] = Directory.fromFiles(
                        fileStore, [(fileName, path)])
            else:
                self[fileName] = File.fromLocalFile(
                        fileStore, fileName, path)

    def importLocalFiles(self, workflow, inputs, rootDir=None):
        """Import local files at the start of the workflow.

        This is usually a first step and is done:
        >>> with Toil(options) as toil:
        ...     storage = Storage.importLocalFiles(
        ...                 toil,
        ...                 ['localfile.tar', 'secondfile', 'ascript.sh'])
        ...     rootJob = RootJob(storage)
        """

        localFiles = []
        remoteFiles = []

        for fileInfo in inputs:

            fileName, url, required = parseFileInfo(fileInfo)

            path = myabspath(url, rootDir)
            if path:
                localFiles.append((fileName, path))
            else:
                remoteFiles.append(fileInfo)

        for fileName, path in localFiles:
            if fileName in self:
                continue

            if os.path.isdir(path):
                self[fileName] = ImportedDirectory.fromFiles(
                        workflow, fileName, [(fileName, path)])
            else:
                try:
                    self[fileName] = ImportedFile.fromLocalFile(
                            workflow, fileName, path)
                except IOError as ioerr:
                    if ioerr.errno != errno.ENOENT:
                        raise

        print("imported localFiles %s" % (", ".join(self)))

        inputs[:] = remoteFiles

        return self

    @classmethod
    def fromLocalFiles(cls, workflow, inputs, rootDir=None):
        storage = cls()
        storage.importLocalFiles(workflow, inputs, rootDir)
        return storage

    def exportLocalFiles(self, workflow, outputDir):
        """Export local files at the end of workflow.

        This is the last step:
        >>> with Toil(options) as toil:
        ...     ...
        ...     storage = toil.start(rootJob)
        ...     storage.exportLocalFiles(toil, 'outputDir')
        """
        try:
            self.fileStore = WorkflowToFileStoreProxy(workflow)
            return self.toDirectory(outputDir, export=True)
        finally:
            del self.fileStore


class File(object):
    """A file in Storage."""
    def __init__(self, fileName, fileId, mode=None):
        super(File, self).__init__()
        self.fileName = fileName
        self.fileId = fileId
        self.mode = mode

    def copy(self, fileStore, dest):
        localCopy = self.localCopy(fileStore)
        if os.path.isdir(dest):
            dest = os.path.join(dest, self.fileName)
        shutil.copy(localCopy, dest)
        if self.mode:
            os.chmod(dest, self.mode)

    def localCopy(self, fileStore):
        return fileStore.readGlobalFile(self.fileId)

    @contextlib.contextmanager
    def open(self, fileStore):
        localFile = self.localCopy(fileStore)
        with open(localFile) as fh:
            yield fh

    @classmethod
    def fromLocalFile(cls, fileStore, fileName, path):
        return cls(fileName, fileStore.writeGlobalFile(path),
                mode=os.stat(path).st_mode)

    def __str__(self):
        return "<File(%s, %s)>" % (self.fileName, self.fileId)

    __repr__ = __str__


class ImportedFile(object):
    def __init__(self, fileName, mode=None):
        super(ImportedFile, self).__init__()
        self.fileName = fileName
        self.mode = mode

    def copy(self, fileStore, dest):
        if os.path.isdir(dest):
            dest = os.path.join(dest, self.fileName)
        with self.open(fileStore) as fhin:
            with open(dest, 'w') as fhout:
                shutil.copyfileobj(fhin, fhout)
        if self.mode:
            os.chmod(dest, self.mode)

    def localCopy(self, fileStore):
        fileName = fileStore.getLocalTempFile()
        self.copy(fileStore, fileName)
        return fileName

    @contextlib.contextmanager
    def open(self, fileStore):
        with fileStore.jobStore.readSharedFileStream(self.fileName) as fh:
            yield fh

    @classmethod
    def fromLocalFile(cls, workflow, fileName, path):
        workflow.importFile('file://' + path, sharedFileName=fileName)

        return cls(
                fileName,
                mode=os.stat(path).st_mode)

    def __str__(self):
        return "<ImportedFile(%s)>" % self.fileName

    __repr__ = __str__


class Directory(object):
    """A directory in Storage. Kept as an archive file."""
    def __init__(self, fileId):
        super(Directory, self).__init__()
        self.fileId = fileId

    def localCopy(self, fileStore, outDir=None):
        localDir = outDir or fileStore.getLocalTempDir()
        localFile = fileStore.readGlobalFile(self.fileId)

        tar = tarfile.TarFile.taropen(localFile)
        tar.extractall(path=localDir)

        return localDir

    def copy(self, fileStore, dest):
        self.localCopy(fileStore, dest)

    @classmethod
    def fromFiles(cls, fileStore, files):

        with fileStore.writeGlobalFileStream() as (fh, fileId):
            tar = tarfile.TarFile.open(fileobj=fh, mode='w')

            for fileName, path in files:
                tar.add(path, arcname=fileName)

        return cls(fileId)

    def __str__(self):
        return "<Directory(%s)>" % self.fileId

    __repr__ = __str__


class ImportedDirectory(Directory):

    def localCopy(self, fileStore, outDir=None):
        localDir = outDir or fileStore.getLocalTempDir()

        with fileStore.jobStore.readSharedFileStream(self.fileId) as fh:
            tar = tarfile.TarFile(fileobj=fh, mode='r')
            tar.extractall(path=localDir)

        return localDir

    @classmethod
    def fromFiles(cls, workflow, dirName, files):
        tmpfile = tempfile.mktemp()

        tar = tarfile.TarFile.open(tmpfile, mode='w')

        for fileName, path in files:
            tar.add(path, arcname=fileName)

        tar.close()

        workflow.importFile('file://' + tmpfile, sharedFileName=dirName)
        os.unlink(tmpfile)

        return cls(dirName)


class IncorrectStorageUse(Exception):
    message = "Child `Job`s with storage added outside of running parent " \
              "wont influence parent's storage. If this is not required " \
              "consider using addChildNoStorage and setting child's " \
              "storage via `self._storage = child.resultStorage`."

    def __init__(self):
        super(IncorrectStorageUse, self).__init__(self.message)


class Job(toilJob):
    """Job with a Storage.

    This Job passes Storage down the workflow via `Promise` mechanism.
    Updates to Storage from the children are merged and passed to the
    followOns.
    """

    _running = False
    def __init__(self, *args, **kwargs):
        super(Job, self).__init__(*args, **kwargs)
        self._storage = Storage()
        self._childStorage = Storage()

    def rv(self, *path):
        return super(Job, self).rv('rv', *path)

    @property
    def storage(self):
        if self._running:
            return self._storage
        else:
            return super(Job, self).rv('storage')

    @property
    def resultStorage(self):
        return super(Job, self).rv('childStorage')

    def _updateStorage(self, succ, promise, ourStorage):
        if not isinstance(succ, Job):
            return

        succ._storage = promise

        if ourStorage is not None:
            if self._running:
                ourStorage.update(succ.storage)
            else:
                raise IncorrectStorageUse()

    def addChild(self, child):
        """Add a child and update storage with it's promised storage"""
        rv = super(Job, self).addChild(child)
        self._updateStorage(child, self.storage, self._childStorage)
        return rv

    def addFollowOn(self, followOn):
        "Add a followOn. FollowOns receive storages with updates from children"
        rv = super(Job, self).addFollowOn(followOn)
        self._updateStorage(followOn, self.resultStorage, None)
        return rv

    def addChildNoStorage(self, child):
        """Add a child that won't contribute to the Storage.

        Typically used to add a child whose Storage will be used as a
        predecessor' result.
        """
        rv = super(Job, self).addChild(child)
        self._updateStorage(child, self.storage, None)
        return rv

    def _run(self, jobGraph, fileStore):

        self._running = True

        storage = self.storage
        storage.fileStore = fileStore

        rv = super(Job, self)._run(jobGraph, fileStore)

        try:
            del storage.fileStore
        except AttributeError:
            pass
        self._running = False

        self._childStorage.update(self._storage)

        return {
                'rv': rv,
                'storage': self._storage,
                'childStorage': self._childStorage
        }


class NoSuchFile(Exception):
    pass


class FileFetcherJob(Job):
    """Fetches files from the Web into the Storage.

    Accepts a list `fileInfo`s to download. There must be no local filesystem
    files. Instead, fetcher should be primed with a Storage having them
    imported via `importLocalFiles`.
    """
    def __init__(self, files, storage=None, localRootDir=None):
        super(FileFetcherJob, self).__init__(cores=1, memory="256M")

        if storage is not None:
            self._storage = storage

        self.files = files
        if localRootDir is None:
            localRootDir = os.path.dirname(os.path.realpath(__file__))
        self.localRootDir = localRootDir

        remoteFiles = self.remoteFiles = []
        localFiles = []

        for fileInfo in self.files:

            fileName, url, required = parseFileInfo(fileInfo)
            if fileName in self._storage:
                continue

            path = myabspath(url, self.localRootDir)
            if path:
                localFiles.append((fileName, path))
            else:
                remoteFiles.append((fileName, url, required))

        if localFiles:
            raise Exception("Non-empty localFiles, did you forgot to importLocalFiles: %s?" % localFiles)


    def run(self, fileStore):

        for fileInfo in self.remoteFiles:

            fileName, url, required = fileInfo
            if fileName in self.storage:
                continue

            try:
                if url.startswith('s3://'):
                    child = S3DownloadJob(fileName, url)
                else:
                    child = DownloadJob(fileName, url)
                self.addChild(child)
            except NoSuchFile:
                if required:
                    raise


class DownloadJob(Job):
    """Download a HTTP or FTP file."""
    def __init__(self, fileName, url):
        self.url = url

        request = requests.get(self.url, stream=True)
        if request.status_code != 200:
            raise NoSuchFile(self.url)

        disk = request.headers.get('Content-Length', '1G')
        request.close()
        self.fileName = fileName

        Job.__init__(self, unitName=url, memory="128M", cores=1, disk=disk)

    def run(self, fileStore):
        r = requests.get(self.url, stream=True)

        with fileStore.writeGlobalFileStream() as (fh, fileId):
            for chunk in r.iter_content(4096):
                fh.write(chunk)
        self.storage[self.fileName] = File(self.fileName, fileId)


_CLIENT = None
class S3FileJob(Job):

    def parseurl(self, desturl):
        url = urlparse.urlparse(desturl)
        if url.scheme != "s3":
            raise Exception("URL %s is not S3 url" % desturl)

        self.url = url
        self.bucket = self.url.netloc
        self.key = self.url.path[1:]
        self.desturl = desturl

    def client(cls):

        global _CLIENT
        if _CLIENT is None:
            _CLIENT = boto3.client('s3')
        return _CLIENT


class S3DownloadJob(S3FileJob):
    """Download a file from AWS S3."""
    def __init__(self, fileName, url):
        self.parseurl(url)

        try:
            self.obj = self.client().get_object(Bucket=self.bucket, Key=self.key)
        except self.client().exceptions.NoSuchKey:
            raise NoSuchFile(url)

        self.fileName = fileName
        super(S3DownloadJob, self).__init__(
                memory="1M", cores=1, unitName="download %s" % url,
                disk=self.obj['ContentLength'])

    def run(self, fileStore):
        with fileStore.writeGlobalFileStream() as (fh, fileId):
            self.client().download_fileobj(Bucket=self.bucket, Key=self.key,
                                           Fileobj=fh)
        self.storage[self.fileName] = File(self.fileName, fileId)


class S3UploadJob(S3FileJob):
    """Upload a file to AWS S3."""
    def __init__(self, fileId, url):
        self.parseurl(url)
        self.fileId = fileId

        super(S3UploadJob, self).__init__(memory="1M", cores=1, unitName="upload %s" % url)


    def run(self, fileStore):
        localFile = fileStore.readGlobalFile(self.fileId)
        self.client().upload_file(localFile, self.bucket, self.key)


class DockerScriptJob(Job):
    """Run docker script on top of an exposed Storage."""

    def __init__(self, script, image,
                 args=[], cores=4, disk="4G",
                 logfileName="docker-logfile"):
        unitName = "image={image} script={script} args={args!r}".format(
                image=image, script=script, args=args)
        Job.__init__(self, cores=cores, disk=disk, unitName=unitName)

        self.script = script

        self.image = image
        self.args = args
        self.logfileName = logfileName

    def run(self, fileStore):

        e = None
        with self.storage.expose() as dockerRoot:
            logfilePath = os.path.join(dockerRoot, self.logfileName)
            with open(logfilePath, "a") as logfilefh:
                dockerDefer = fileStore.jobStore.config.dockerDefer

                dockerParameters = []
                if dockerDefer == RM:
                    dockerParameters.append('--rm')

                dockerParameters += ['-t', '-v', os.path.abspath(dockerRoot) + ':/data']
                #dockerParameters += ['--privileged']
                dockerParameters += ['--cap-add=SYS_PTRACE']

                dockerCall(self,
                        tool=self.image, workDir=dockerRoot,
                        defer=dockerDefer, outfile=logfilefh,
                        parameters=["/data/build"]
                                   + self.args,
                        dockerParameters=dockerParameters)

        return str(e)

    def __str__(self):
        name = "build--script=%s--image=%s" % (
                os.path.basename(self.script), self.image)
        return name.replace(':', '-').replace('=', '-').replace('/', '-')



DEFAULT_SCRIPT = './build-patch.sh'
DEFAULT_IMAGE = 'centos:centos7'

UploadInfo = collections.namedtuple('UploadInfo', ('fileName', 'url'))

class UploadJob(Job):
    """Upload files from the Storage.

    URLs passed are `uploadInfo` instances.
    """
    def __init__(self, urls):
        self.urls = [UploadInfo(*url) for url in urls]

        super(UploadJob, self).__init__()

    def run(self, fileStore):
        for url in self.urls:
            fileName, url = url

            fileObj = self.storage.get(fileName)
            if fileObj is None:
                continue

            path = myabspath(url)
            if not path:
                self.addChild(S3UploadJob(fileObj.fileId, url))
            else:
                localFile = fileStore.readGlobalFile(fileObj.fileId)
                shutil.copy(localFile, path)


class DoBuild(Job):
    """If prebuild archive is not in storage do a prebuild and upload it to the
    specified location. Otherwise just do a build."""

    def __init__(self, fileName, prebuildJob, uploadJob, buildJob):
        super(DoBuild, self).__init__(memory="256M")

        self.fileName = fileName
        self.prebuildJob = prebuildJob
        self.buildJob = buildJob
        self.uploadJob = uploadJob

    def run(self, fileStore):
        if self.fileName not in self.storage:
            self.addChild(self.prebuildJob)

            self.prebuildJob.addChildNoStorage(self.buildJob)
            self.prebuildJob.addChildNoStorage(self.uploadJob)
        else:
            self.addChild(self.buildJob)

        self._storage = self.buildJob.storage


class BuildPatchJob(toilJob):
    """Root job for patch building. Fetches files and runs Docker jobs.

    The algorithm is the following:
    1. FileFetcherJob(inputs + optional prebuild).

    2. If prebuild is there, just run DockerScriptJob with a build job.

    3. If prebuild is missing, run DockerScriptJob. Chain UploadJob for it.
       Start build job DockerScriptJob it.
    """
    def __init__(self, storage, packageDescription):
        super(BuildPatchJob, self).__init__(memory="256M")

        self.storage = storage
        self.packageDescription = packageDescription

        self.script = packageDescription.get('script', DEFAULT_SCRIPT)
        self.image = packageDescription.get('image', DEFAULT_IMAGE)

        self.inputs = list(packageDescription.get('input'))

    def run(self, fileStore):

        tail = self

        fetcher = FileFetcherJob(self.inputs, storage=self.storage)
        tail.addFollowOn(fetcher)
        tail = fetcher

        prebuildUrl = self.packageDescription['prebuild']
        prebuildName = os.path.basename(prebuildUrl)

        prebuildJob = DockerScriptJob(
                script=self.script,
                image=self.image,
                args=['-p'],
                logfileName="prebuild.log")
        uploadJob = UploadJob([(prebuildName, prebuildUrl)])

        buildJob = DockerScriptJob(
                script=self.script,
                image=self.image,
                logfileName="build.log")


        doBuild = DoBuild(fileName=prebuildName, prebuildJob=prebuildJob,
                          uploadJob=uploadJob, buildJob=buildJob)
        tail.addFollowOn(doBuild)
        tail = doBuild

        return tail.storage


def get_default_outputDir():
    outputDir = os.path.join(os.getcwd(), 'libcare-output')
    outputDir = os.path.join(outputDir, datetime.datetime.utcnow().isoformat())
    return outputDir

def readPackageDescription(packageFile):
    with open(packageFile) as fh:
        packageDescription = yaml.load(fh)

    inputs = packageDescription['input']

    cwd = os.path.dirname(os.path.realpath(__file__))

    script = packageDescription.get(
            'script', os.path.join(cwd, DEFAULT_SCRIPT))

    inputs.append({'build': script})
    inputs.append({'scripts': os.path.join(cwd, '../../scripts')})
    inputs.append({'src': os.path.join(cwd, '../../src/')})
    inputs.append({'execve': os.path.join(cwd, '../../tests/execve')})

    prebuildUrl = packageDescription['prebuild']
    if not prebuildUrl.startswith('*'):
        prebuildUrl = '*' + prebuildUrl
    inputs.append(prebuildUrl)

    return packageDescription

def start(toil):

    options = toil.options

    packageDescription = readPackageDescription(options.packageFile)

    path = myabspath(options.outputDir)
    if path:
        print("output directory is", path)
        options.outputDir = path
    else:
        print("output url is", options.outputDir)

    rootDir = os.path.realpath(os.path.dirname(options.packageFile))

    storage = Storage()
    storage.importLocalFiles(toil, packageDescription['input'], rootDir=rootDir)
    theJob = BuildPatchJob(storage, packageDescription)

    return toil.start(theJob)

def restart(toil):
    packageDescription = readPackageDescription(toil.options.packageFile)

    rootDir = os.path.realpath(os.path.dirname(toil.options.packageFile))

    Storage.fromLocalFiles(toil, packageDescription['input'], rootDir=rootDir)

    return toil.restart()

def main():
    parser = Job.Runner.getDefaultArgumentParser()
    parser.add_argument('packageFile')
    parser.add_argument('--outputDir', required=False,
            default=get_default_outputDir())
    parser.add_argument('--dockerDefer', required=False,
            default='RM')
    options = parser.parse_args()

    options.disableCaching = True

    with Toil(options) as toil:
        toil.config.dockerDefer = globals()[options.dockerDefer.upper()]
        toil._jobStore.writeConfig()

        if not toil.options.restart:
            storage = start(toil)
        else:
            storage = restart(toil)

        try:
            os.makedirs(options.outputDir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        storage.exportLocalFiles(toil, options.outputDir)

if __name__ == "__main__":
    main()
