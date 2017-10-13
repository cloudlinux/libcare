#!/usr/bin/python

import contextlib
import functools
import os
import shutil
from StringIO import StringIO
import tempfile

from toil.common import Toil

import pkgbuild

def test_storage_update():
    Storage = pkgbuild.Storage

    storage = Storage(**{'test.sh': 'nothing'})
    newStorage = Storage(**{'test2.sh': 'nothing'})

    storage.update('promised_value2')
    newStorage.update('promised_value')

    newStorage.update(storage)

    assert newStorage == {'test.sh': 'nothing', 'test2.sh': 'nothing'}
    assert newStorage.promised_updates == ['promised_value', 'promised_value2']
    assert Storage(newStorage) == newStorage

def test_storage_pickle():
    import cPickle
    Storage = pkgbuild.Storage

    storage = Storage()
    storage['abc'] = 'test'
    storage.update('promised_value')

    storage = cPickle.loads(cPickle.dumps(storage, protocol=-1))
    assert storage['abc'] == 'test'
    assert storage.promised_updates == ['promised_value']

def test_parseFileInfo():
    parseFileInfo = pkgbuild.parseFileInfo

    info = parseFileInfo('http://kernel.org/index.html')
    assert info == pkgbuild.FileInfo(
            fileName='index.html',
            url='http://kernel.org/index.html',
            required=True)

    info = parseFileInfo('*http://kernel.org/index.html')
    assert info == pkgbuild.FileInfo(
            fileName='index.html',
            url='http://kernel.org/index.html',
            required=False)

    info = parseFileInfo({'foobar.html': 'http://kernel.org/index.html'})
    assert info == pkgbuild.FileInfo(
            fileName='foobar.html',
            url='http://kernel.org/index.html',
            required=True)

    info = parseFileInfo({'foobar.html': '*http://kernel.org/index.html'})
    assert info == pkgbuild.FileInfo(
            fileName='foobar.html',
            url='http://kernel.org/index.html',
            required=False)

    try:
        info = parseFileInfo({
            'foobar.html': '*http://kernel.org/index.html',
            'other': 'things'})
    except ValueError:
        pass
    else:
        assert False

class FakeJobStorage(object):
    def __init__(self, imported):
        self.imported = imported

    @contextlib.contextmanager
    def readSharedFileStream(self, fileId):
        buf = fileId
        if self.imported and fileId in self.imported:
            buf = self.imported[fileId]
        yield StringIO(buf)

class FakeFileStorage(object):
    def __init__(self, imported=None):
        self.localTempDir = tempfile.mkdtemp()
        self.jobStore = FakeJobStorage(imported)

    def getLocalTempDir(self):
        return self.localTempDir

    def readGlobalFile(self, fileId):
        fileName = tempfile.mktemp()
        with open(fileName, "w") as fh:
            print(fileId)
            fh.write(fileId)
        return fileName

    def writeGlobalFile(self, path):
        with open(path) as fh:
            return fh.read()

    @contextlib.contextmanager
    def writeGlobalFileStream(self):
        fh_and_fileId = StringIO()
        yield fh_and_fileId, fh_and_fileId

class FakeWorkflow(object):
    def __init__(self):
        self.imported = {}

    def importFile(self, path, sharedFileName):
        self.imported[sharedFileName] = slurp(path.replace('file://', ''))

def slurp(fileName):
    return open(fileName).read()

def test_storage():
    storage = pkgbuild.Storage(
        **{
            'file.txt': pkgbuild.File('file.txt', 'some content'),
            'imported.txt': pkgbuild.ImportedFile('imported.txt')
        }
    )
    storage.fileStore = FakeFileStorage()

    with storage.expose() as dirname:

        assert set(os.listdir(dirname)) == set(['file.txt', 'imported.txt'])

        assert slurp(os.path.join(dirname, 'file.txt')) == 'some content'
        assert slurp(os.path.join(dirname, 'imported.txt')) == 'imported.txt'

        with open(os.path.join(dirname, 'newfile.txt'), 'w') as fh:
            fh.write('and some content here')


    assert storage['newfile.txt'].fileId == 'and some content here'

    with storage.expose() as dirname:


        newdir = os.path.join(dirname, 'testdir')
        os.mkdir(newdir)
        with open(os.path.join(newdir, 'subfile'), "w") as fh:
            fh.write('foobar')

        inputs = os.listdir(dirname) + ['http://somefile.com/index.html']
        workflow = FakeWorkflow()
        newStorage = pkgbuild.Storage.fromLocalFiles(
                workflow, inputs, dirname)
        assert inputs == ['http://somefile.com/index.html']


    assert isinstance(newStorage['testdir'], pkgbuild.ImportedDirectory)

    newStorage.fileStore = FakeFileStorage(workflow.imported)
    with newStorage.expose() as dirname:

        assert slurp(os.path.join(dirname, 'file.txt')) == 'some content'
        assert slurp(os.path.join(dirname, 'imported.txt')) == 'imported.txt'
        assert slurp(os.path.join(dirname, 'newfile.txt')) == 'and some content here'
        assert slurp(os.path.join(dirname, 'testdir', 'subfile')) == 'foobar'


class DummyStorageUpdate(pkgbuild.Job):
    def __init__(self, filename):
        super(DummyStorageUpdate, self).__init__(unitName=filename)
        self.filename = filename

    def run(self, fileStore):
        self.storage[self.filename] = 'something'

class DummyStorageAsChild(pkgbuild.Job):
    def run(self, fileStore):
        a = DummyStorageUpdate('bar')
        self.addChild(a)

class RootJob(pkgbuild.Job):
    def __init__(self, storage):
        super(RootJob, self).__init__()
        self._storage = storage

    def run(self, fileStore):

        tail = self

        a = DummyStorageUpdate('foo')
        self.addChild(a)
        tail = a

        b = DummyStorageAsChild()
        tail.addFollowOn(b)
        tail = b

        return tail.resultStorage

def test_job_storage():
    parser = pkgbuild.Job.Runner.getDefaultArgumentParser()
    options = parser.parse_args(['test_job_storage'])

    options.workDir = tempfile.mkdtemp()
    options.jobStore = os.path.join(options.workDir, 'workdir')

    storage = pkgbuild.Storage(foobar='here i go')
    root = RootJob(storage=storage)

    try:
        with Toil(options) as toil:
            storage = toil.start(root)
    finally:
        shutil.rmtree(options.workDir)

    assert storage == {'foo': 'something', 'bar': 'something', 'foobar': 'here i go'}
