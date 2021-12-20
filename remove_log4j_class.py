#!/usr/bin/env python
#
# Copyright (c) 2021 VMware, Inc.  All rights reserved.

"""
Handles CVE-2021-44228 exploit for VMware vCenter Server deployed
either on linux or windows environment.

Script works by first stopping all services. It then traverses either
supplied directories list or default ones for linux and windows environments.
Directories are searched for java archives which contain JndiLookup.class file.
File is removed from the archives. A backup is created beforehand for each archive.
Backup is located in a temporary folder and preserves the file hierarchy to facilitate
future rollback.
Once the procedure is completed services are started back.
"""

import os
import sys
import zipfile
import tempfile
import shutil
import subprocess
import logging
import argparse
from datetime import datetime
from itertools import chain

SCRIPT_VERSION = "1.0.0 RC3"
JNDI_PATH = "org/apache/logging/log4j/core/lookup/JndiLookup.class"
BACKUP_DIR = "" # This is initialized below
LOG_DIR = os.environ.get('VMWARE_LOG_DIR')
LOG_NAME = "vmsa-2021-0028"

LOG = logging.getLogger(__name__)


def is_windows():
    """
    Checks whether script runs on windows environment
    """
    return sys.platform in ['win32', 'cygwin', 'windows']


class Services(object):
    """Helper class for start/stop all services using service-control"""

    def __init__(self):
        if is_windows():
            self.service_control = \
                os.path.join(os.environ['VMWARE_CIS_HOME'], 'bin', 'service-control.bat')
        else:
            self.service_control = "/usr/bin/service-control"

    @classmethod
    def run_command(cls, cmd):
        """
        execute a command with the given input and return the return code and output
        """
        LOG.debug("Running command: %s", str(cmd))

        # Note: close_fds is always set to False for windows. This is because
        # stdin/stdout flags don't work with close_fds on Windows.

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   close_fds=False)
        stdout, stderr = process.communicate()
        ret = process.returncode
        LOG.debug("Done running command")
        if isinstance(stdout, str):
            stdout = stdout.decode(sys.getfilesystemencoding())
        if isinstance(stderr, str):
            stderr = stderr.decode(sys.getfilesystemencoding())
        if ret != 0:
            LOG.error("RC = %s\nStdout = %s\nStderr = %s", ret, stdout, stderr)
        return ret, stdout, stderr

    def stop(self):
        """
        Runs external script which stops system services
        """
        LOG.info("stopping services")

        cmd = [self.service_control, '--stop', '--all']
        ret, stdout, _ = Services.run_command(cmd)

        if ret != 0:
            LOG.error("error occurred while trying to stop vmware services")
            sys.exit(ret)

        LOG.debug(stdout)

    def start(self):
        """
        Runs external script which start system services
        """
        LOG.info("starting services")
        cmd = [self.service_control, '--start', '--all']
        ret, stdout, _ = Services.run_command(cmd)

        if ret != 0:
            LOG.error("error occurred while trying to start services")
            sys.exit(ret)

        LOG.debug(stdout)


def prompt_service_restart(accept_services_restart, start=False):
    """
    Prompts user that a service stop and start operations would be required
    """
    service_action = Services()
    if not start:
        user_choice = 'y'
        if not accept_services_restart:
            try:
                user_choice = \
                    raw_input("A service stop and start is required to "
                              "complete this operation.  Continue?[y]")
            except NameError:
                user_choice = \
                    input("A service stop and start is required to "
                          "complete this operation.  Continue?[y]")
            LOG.debug("User chose '%s'", user_choice)
        else:
            LOG.debug("Skipping user choice and assuming stop and start of services")

        if user_choice.lower() == 'y':
            service_action.stop()
        else:
            LOG.info("Cannot continue without stopping services. Exiting...")
            sys.exit()
    else:
        service_action.start()


def setup_logging():
    """
    Sets logging to write to vmware log system directory, current working directory, and console
    """

    def set_handler(handler, loglevel):
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(funcName)s: %(message)s",
            datefmt='%Y-%m-%dT%H:%M:%S')
        handler.setFormatter(formatter)
        handler.setLevel(loglevel)
        LOG.addHandler(handler)

    LOG.setLevel(logging.DEBUG)

    file_name = LOG_NAME + "_" + datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S") + '.log'
    if LOG_DIR:
        # LOG for support bundles
        file_path = os.path.join(LOG_DIR, file_name)
        file_handler = logging.FileHandler(file_path)
        set_handler(file_handler, logging.DEBUG)
    # LOG in current working directory
    file_path = os.path.join(os.getcwd(), file_name)
    file_handler = logging.FileHandler(file_path)
    set_handler(file_handler, logging.DEBUG)

    # console handler
    console_handler = logging.StreamHandler(sys.stdout)
    set_handler(console_handler, logging.INFO)


def is_java_archive(filename):
    """
    Return true if the given filename ends with either .jar or .war
    :type filename: str
    :rtype: bool
    """
    zip_exts = (".jar", ".war")
    return filename.lower().endswith(tuple(zip_exts))


def find_zip_files(dirnames, parent_type=None, dryrun=False):
    """
    Find and process all files under given dirnames to find the offending log4j
    class.
    :type dirnames: list[str]
    :param parent_type: whether the parent of these dirnames come from a .war file.
        The value is only "war" or None.
    :type parent_type: str
    :param dryrun: A boolean to indicate whether the archive should be mitigated. False means to mitigate it.
    :type dryrun: bool
    :return: List of filepaths that have been processed
    :rtype: list[str]
    """
    if not isinstance(dirnames, list):
        dirnames = [dirnames]
    processed_files = []
    for root, _, files in chain.from_iterable(os.walk(path) for path in dirnames):
        for file_name in files:
            if is_java_archive(file_name):
                if not os.path.getsize(os.path.join(root,file_name)) == 0:
                    processed = process_archive(file_name, root, parent_type, dryrun)
                    if processed is not None:
                        processed_files.append(processed)
                else:
                    LOG.debug("File: %s is 0 bytes in size.  Skipping..." % file_name)
                    continue
    return processed_files


def has_vulnerable_class(filename):
    """
    Returns true if given filepath contains the offending log4j class.
    :param filename: name of a zip file to process
    :type filename: str
    :rtype: bool
    """
    with zipfile.ZipFile(filename, 'r') as zip_obj:
        # Get list of files names in zip
        list_of_files = zip_obj.namelist()
        return any(f.endswith(JNDI_PATH) for f in list_of_files)


def move_to_backup(filepath):
    """
    Move given filepath to under BACKUPDIR with preserving the file hierarchy.
    :type filepath: str
    :return: The backed up filepath under BACKUPDIR
    :rtype: str
    """
    normpath = os.path.normpath(filepath)
    normpath = os.sep.join(normpath.split(os.sep)[1:])
    backuppath = os.path.join(BACKUP_DIR, normpath + ".bak")
    # move file to .bak and remove original
    try:
        if not os.path.exists(os.path.dirname(backuppath)):
            os.makedirs(os.path.dirname(backuppath))

        shutil.move(filepath, backuppath)
    except OSError:
        LOG.error("Failed to create backup of %s. Check if backup already exists.", filepath)
        return None
    return backuppath


def set_file_perms(filepath, stat):
    """
    Setting the given stat to the filepath.
    :type filepath: str
    :type stat: os.stat_result
    """
    os.chmod(filepath, stat.st_mode)
    if not is_windows():
        os.chown(filepath, stat.st_uid, stat.st_gid)


def create_archive(pathname, directory):
    """
    Archive given directory to pathname.
    :type pathname: str
    :type directory: str
    """
    orig_dir = os.getcwd()
    os.chdir(directory)
    with zipfile.ZipFile(pathname, 'w') as zip_obj:
        # Iterate over all the files in directory
        for folder_name, _, filenames in os.walk(directory):
            for filename in filenames:
                # create complete filepath of file in directory
                file_path = os.path.join(folder_name, filename)
                # Add file to zip
                zip_obj.write(file_path, file_path.replace(directory, ''))
    os.chdir(orig_dir)


def process_war(filepath, dryrun=False):
    """
    This func processes a .war file by following steps:
    1. Create a temporary dir
    2. Extract the .war to #1
    3. Move .war to BACKUPDIR
    4. Find and process the files in #1, so the jars will be off of offending class, if any.
    5. Archive the temporary dir #1 back to the original filename
    :type filepath: str
    :param dryrun: A boolean to indicate whether the archive should be mitigated. False means to mitigate it.
    :type dryrun: bool
    :return: None if the war does not contain any offending class and was not changed at all;
        the filepath if the war was handled.
    """
    results = None
    # create a temp dir to extract war file
    dirpath = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(filepath) as war_zip:
            war_zip.extractall(dirpath)
    except (zipfile.error, OSError):
        LOG.warning("Bad zip file: %s", filepath)
        return None
    stat = os.stat(filepath)
    processed_files = find_zip_files(dirpath, 'war', dryrun)
    if len(processed_files) > 0:
        LOG.info("Found a VULNERABLE WAR file with: %s", filepath)
        results = filepath
        if not dryrun:
            backuppath = move_to_backup(filepath)
            if backuppath is None:
                LOG.error("could not process file %s", filepath)
                return None
            create_archive(filepath, dirpath)
            set_file_perms(filepath, stat)
            LOG.info("VULNERABLE FILE: %s backed up to %s", filepath, backuppath)
    shutil.rmtree(dirpath, ignore_errors=True)
    return results


def process_archive(filename, root, parent_type, dryrun=False):
    """
    Processes the filename under root
    :type filename: str
    :type root: str
    :param parent_type: Whether filename comes from a .war, value can only be None or war
    :type parent_type: str
    :param dryrun: A boolean to indicate whether the archive should be mitigated. False means to mitigate it.
    :type dryrun: bool
    :return: filepath if it was handled; None otherwise
    """
    filepath = root + os.path.sep + filename
    if filepath.endswith('.war'):
        return process_war(filepath, dryrun)

    try:
        if not has_vulnerable_class(filepath):
            return None
    except (zipfile.error, OSError):
        LOG.debug("Bad zip file: %s", filepath)
        return None
    LOG.info("Found a VULNERABLE FILE: %s", filepath)
    if dryrun:
        # if dryrun, we don't want to change the file, just report it.
        return filepath
    stat = os.stat(filepath)
    backuppath = move_to_backup(filepath)
    if backuppath is None:
        LOG.error("could not process file %s", filepath)
        return None
    zin = zipfile.ZipFile(backuppath, 'r')
    zout = zipfile.ZipFile(filepath, 'w')
    for item in zin.infolist():
        if not item.filename.endswith(JNDI_PATH):
            buffer = zin.read(item.filename)
            zout.writestr(item, buffer)
    set_file_perms(filepath, stat)
    zout.close()
    zin.close()
    # don't keep backups of jar inside war
    if parent_type == 'war':
        os.remove(backuppath)
    else:
        LOG.info("VULNERABLE FILE: %s backed up to %s", filepath, backuppath)
    return filepath


def parse_args(args):
    """
    Parse arguments
    """
    parser = argparse.ArgumentParser(description="""
        VMSA-2021-0028 vCenter tool; Version: %s
        This tool deletes the JndiLookup.class file from *.jar and *.war
        files.

        On Windows systems the tool will by default traverse the folders
        identified by the VMWARE_CIS_HOME, VMWARE_CFG_DIR, VMWARE_DATA_DIR
        and VMWARE_RUNTIME_DATA_DIR variables.

        On vCenter Appliances the tool will search by default from the root
        of the filesystem.

        All modified files are backed up if the process needs to be reversed
        due to an error.
    """ % SCRIPT_VERSION)

    parser.add_argument("-d", "--directories",
                        nargs="+",
                        default=[],
                        help="space separated list of directories to check recursively "
                             "for CVE-2021-44228 vulnerable files.",
                        metavar="dirnames")
    parser.add_argument("-a", "--accept-services-restart",
                        action="store_true",
                        help="acccept the restart of the services without having "
                             "manual confirmation for the same")
    parser.add_argument("-r", "--dryrun",
                        action="store_true",
                        help="Run the script and log vulnerable files without mitigate them.")
    parser.add_argument("-b", "--backup-dir",
                        help="Specify a backup directory to store original files.")
    return parser.parse_args(args)


def get_dirnames(args):
    """
    Gets a list of directories to check for exploit.
    If no explicit parameter provided uses root folder for linux
    and a list of environment variables provided folders for windows
    """
    dirnames = args.directories if args.directories is not None else []

    if not dirnames:
        if is_windows():
            dirnames = []
            for env_var in ['VMWARE_CIS_HOME',
                            'VMWARE_CFG_DIR',
                            'VMWARE_DATA_DIR',
                            'VMWARE_RUNTIME_DATA_DIR']:
                val = os.environ.get(env_var)
                if val is not None:
                    dirnames.append(val)
            if not dirnames:
                dirnames = [os.getcwd()]
        else:
            dirnames = [os.path.abspath(os.sep)]

    for dirname in dirnames:
        if not os.path.isdir(dirname):
            LOG.debug("Error: provided '%s' path is not a directory", dirname)
            sys.exit()

    return dirnames


def main(args):
    """
    Main function
    """
    global BACKUP_DIR

    args = parse_args(args)
    dryrun = args.dryrun

    LOG.info("Script version: %s", str(SCRIPT_VERSION))
    setup_logging()

    if not dryrun:
        prompt_service_restart(args.accept_services_restart)
    else:
        LOG.info("Running in dryrun mode")

    if args.backup_dir:
        BACKUP_DIR = args.backup_dir
        # make sure BACKUP_DIR exists
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
    else:
        BACKUP_DIR = tempfile.mkdtemp()

    dirnames = get_dirnames(args)

    LOG.debug("Inspecting folders: %s", str(dirnames))
    processed = find_zip_files(dirnames, None, dryrun)

    summary = "\n=====     Summary     =====\n"
    if dryrun:
        summary += "List of vulnerable files:\n"
    else:
        summary += "Backup Directory: %s\n" % BACKUP_DIR
        summary += "List of processed files:\n"
    for p in processed:
        summary += "%s\n" % p
    summary += "==========================="
    LOG.info(summary)

    if not dryrun:
        prompt_service_restart(args.accept_services_restart, start=True)
    LOG.info("Done.")


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception as e:
        LOG.exception("Unhandled exception occurred while running the script: %s", e)
