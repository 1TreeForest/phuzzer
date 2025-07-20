
from queue import Queue, Empty
from threading import Thread
from .afl import AFL
import archr
import json
import os
import re
import subprocess
import shutil
import time
import stat
import glob
import logging
import urllib.request
#import ipdb

from ctypes import c_bool
from multiprocessing import Process, Value

l = logging.getLogger("phuzzer.phuzzers.wafl")
l.setLevel(logging.INFO)

class WitcherAFL(AFL):
    """ WitcherAFL launches the web fuzzer building on the AFL object """

    def __init__(
        self, target, seeds=None, dictionary=None, create_dictionary=None,
        work_dir=None, resume=False,
        afl_count=1, memory="8G", timeout=None,
        target_opts=None, extra_opts=None,
        crash_mode=False, use_qemu=True,
        run_timeout=None, login_json_fn="",
        server_cmd=None, server_env_vars=None,
        base_port=None, container_info=None, fault_escalation=True,
        dual_url_config=None
    ):
        """
        :param target: path to the script to fuzz (from AFL)
        :param seeds: list of inputs to seed fuzzing with (from AFL)
        :param dictionary: a list of bytes objects to seed the dictionary with (from AFL)
        :param create_dictionary: create a dictionary from the string references in the binary (from AFL)
        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here (from AFL)

        :param resume: resume the prior run, if possible (from AFL)
        :param afl_count:

        :param memory: AFL child process memory limit (default: "8G")
        :param afl_count: number of AFL jobs total to spin up for the binary
        :param timeout: timeout for individual runs within AFL

        :param library_path: library path to use, if none is specified a default is chosen
        :param target_opts: extra options to pass to the target
        :param extra_opts: extra options to pass to AFL when starting up

        :param crash_mode: if set to True AFL is set to crash explorer mode, and seed will be expected to be a crashing input
        :param use_qemu: Utilize QEMU for instrumentation of binary.

        :param run_timeout: amount of time for AFL to wait for a single execution to finish
        :param login_json_fn: login configuration file path for automatically craeting a login session and performing other initial tasks

        """

        self.container_info = None

        if container_info:
            self.container_info = container_info
            self.afl_path = os.path.join("/afl", "afl-fuzz")

        elif "AFL_PATH" in os.environ:
            afl_fuzz_bin = os.path.join(os.environ['AFL_PATH'], "afl-fuzz")
            if os.path.exists(afl_fuzz_bin):
                self.afl_path = afl_fuzz_bin
            else:
                raise ValueError(
                    f"error, have AFL_PATH but cannot find afl-fuzz at {os.environ['AFL_PATH']} with {afl_fuzz_bin}")

        super().__init__(
            target=target, work_dir=work_dir, seeds=seeds, afl_count=afl_count,
            create_dictionary=create_dictionary, timeout=timeout,
            memory=memory, dictionary=dictionary, use_qemu=use_qemu,
            target_opts=target_opts, resume=resume, crash_mode=crash_mode, extra_opts=extra_opts,
            run_timeout=run_timeout, container_info=container_info
        )

        self.login_json_fn = login_json_fn

        self.used_sessions = set()
        self.session_name = ""
        self.bearer = ""

        self.server_cmd = server_cmd
        self.server_env_vars = server_env_vars
        self.server_procs = []
        self.base_port = base_port if base_port is not None else os.environ.get("PORT",14000)
        self.container_targets = []
        self.running_flag = Value(c_bool, True)
        self.relog = False
        print(f"\033[38;5;11mFAULT ESCALATION is {fault_escalation}")
        self.fault_escalation = fault_escalation
        self.dual_url_config = dual_url_config or {}
        if container_info:
            self.relog = True


    def check_environment(self):
        if self.container_info:
            return True
        return super().check_environment

    def _start_container(self, scr_fn, log_fpath, fuzzer_id, instance_cnt):
        t: archr.targets.DockerImageTarget = archr.targets.DockerImageTarget(
            image_name=self.container_info["name"],
        )

        # t.volumes["/p"] = {'bind': "/p", 'mode': 'rw'}
        # t.volumes[self.work_dir] = {'bind': self.work_dir, 'mode': 'rw'}
        t.volumes[self.work_dir] = {'bind': self.work_dir, 'mode': 'rw'}


        print(f"mounted workdir {self.work_dir}")
        t.build()

        t.start(
            labels=[f"witcher-iot-{fuzzer_id}"]
        )
        self._configure_container(t)

        self.container_targets.append(t)

        p = t.run_command(["/bin/sh", "-c", 'echo 1 >/proc/sys/kernel/sched_child_runs_first && echo core > /proc/sys/kernel/core_pattern'])
        p.communicate()
        p = t.run_command(["/bin/sh", "-c", "for fn in /sys/devices/system/cpu/cpu*/cpufreq/scaling_gov*; do echo performance > $fn; done"])
        p.communicate()
        t.run_command(["/bin/sh", "/entrypoint.sh"])
        #t.run_command(["/bin/ash", "-c", f"while /bin/true; do AFL_META_INFO_ID=80 /sbin/httpd; done"])
        time.sleep(4)
        import tarfile
        tar_fpath = os.path.join("/tmp","witcher.tar")
        #with tarfile.open(tar_fpath, "w") as tar:
        #    tar.add("/lib/x86_64-linux-gnu/libdl-2.31.so", arcname="libdl-2.31.so")
        t.inject_tarball("/tmp", tar_fpath)
        #t.run_command(["ln", "-s", "/tmp/libdl-2.31.so","/lib/x86_64-linux-gnu/libdl.so.2"])
        t.run_command(["/bin/sh", "-c", "cd /bin && rm -f sh && ln -s /bin/dash /bin/sh"])


        # run fuzzer
        print("started qemu-user server...")
        return t.ipv4_address



    def _start_afl_instance(self, instance_cnt=0):

        args, fuzzer_id = self.build_args()

        logpath = os.path.join(self.work_dir, fuzzer_id + ".log")

        my_env = os.environ.copy()

        final_args = []

        for op in args:
            target_var = op.replace("~~", "--").replace("@@PORT@@", str(self.base_port))
            increasing_port = self.base_port + instance_cnt

            if "@@PORT_INCREMENT@@" in target_var:
                target_var = target_var.replace("@@PORT_INCREMENT@@", str(increasing_port))
                my_env["PORT"] = str(increasing_port)
                my_env["AFL_META_INFO_ID"] = str(increasing_port)
            final_args.append(target_var)

        theip = None
        with open(logpath, "w") as fp:
            if self.container_info and self.container_info.get("name", None):
                theip = self._start_container("", fp, fuzzer_id, instance_cnt)

        #print(f"TARGET OPTS::::: {final_args}")

        self._get_login(my_env, theip)
        my_env["AFL_BASE"] = os.path.join(self.work_dir, fuzzer_id)
        if self.fault_escalation:
            my_env["STRICT"] = "3"
        elif "STRICT" in my_env:
            del my_env["STRICT"]

        my_env["SCRIPT_NAME"] = my_env.get("SCRIPT_FILENAME","")
        if my_env["SCRIPT_NAME"].startswith("/app"):
            my_env["SCRIPT_NAME"] = my_env.get("SCRIPT_FILENAME","").replace("/app","")

        if "METHOD" not in my_env:
            my_env["METHOD"] = "POST"

        # print(f"[WC] my word dir {self.work_dir} AFL_BASE={my_env['AFL_BASE']}")

        self.log_command(final_args, fuzzer_id, my_env)

        l.debug("execing: %s > %s", ' '.join(final_args), logpath)

        # set core affinity if environment variable is set
        if "AFL_SET_AFFINITY" in my_env:
            tempint = int(my_env["AFL_SET_AFFINITY"])
            tempint += instance_cnt
            my_env["AFL_SET_AFFINITY"] = str(tempint)

        scr_fn = f"{self.work_dir}/fuzz-{instance_cnt}.sh"
        with open(scr_fn, "w") as scr:
            if self.container_info:
                scr.write("#! /bin/sh \n")
            else:
                scr.write("#! /bin/bash \n")
                # this will prevent multiple fuzzers running at once, should make it appear in work dir
                scr.write("rm -f /tmp/httpreqr.pid || sudo rm -f /tmp/httpreqr.pid \n")
            for key, val in my_env.items():
                scr.write(f'export {key}="{val}"\n')
            scr.write(" ".join(final_args) + "\n")
            scr.write("rm -f /tmp/httpreqr.pid || sudo rm -f /tmp/httpreqr.pid \n")
            #scr.write(f"{final_args[0].replace('afl-fuzz','afl-showmap')} -o /tmp/outmap ")

        # Create shadow fuzzer instance for dual URL mode
        shadow_scr_fn = None
        shadow_proc = None
        if "PRIMARY_URL" in my_env and "SECONDARY_URL" in my_env:
            primary_url = my_env["PRIMARY_URL"]
            secondary_url = my_env["SECONDARY_URL"]
            
            # Use the same work directory for both main and shadow fuzzer
            shadow_work_dir = self.work_dir
            
            # Create shadow fuzzer script in the same work directory
            shadow_scr_fn = f"{shadow_work_dir}/fuzz-{instance_cnt}-shadow.sh"
            shadow_env = my_env.copy()
            
            # Update environment for shadow fuzzer
            shadow_env["SCRIPT_FILENAME"] = secondary_url
            shadow_env["SCRIPT_NAME"] = secondary_url
            if shadow_env["SCRIPT_NAME"].startswith("/app"):
                shadow_env["SCRIPT_NAME"] = shadow_env["SCRIPT_NAME"].replace("/app","")
            
            shadow_env["AFL_BASE"] = os.path.join(self.work_dir, fuzzer_id + "-shadow")
            
            # Create shadow fuzzer script
            with open(shadow_scr_fn, "w") as shadow_scr:
                if self.container_info:
                    shadow_scr.write("#! /bin/sh \n")
                else:
                    shadow_scr.write("#! /bin/bash \n")
                    shadow_scr.write("rm -f /tmp/httpreqr.pid || sudo rm -f /tmp/httpreqr.pid \n")
                
                for key, val in shadow_env.items():
                    shadow_scr.write(f'export {key}="{val}"\n')
                
                # Modify AFL arguments for shadow fuzzer
                # Shadow fuzzer should be identical to main fuzzer except for output directory
                shadow_args = []
                i = 0
                while i < len(final_args):
                    arg = final_args[i]
                    if arg == "-o" and i + 1 < len(final_args):
                        # Output directory should be the same as main fuzzer (both use work_dir)
                        # AFL will create subdirectories within this for different fuzzers
                        shadow_args.append(arg)
                        shadow_args.append(final_args[i + 1])  # Keep same work_dir, no -shadow suffix
                        i += 2
                    elif (arg == "-M" or arg == "-S") and i + 1 < len(final_args):
                        # Fuzzer name flag, add shadow suffix to distinguish from main fuzzer
                        shadow_args.append(arg)
                        shadow_args.append(final_args[i + 1] + "-shadow")
                        i += 2
                    else:
                        # All other arguments should be identical to main fuzzer
                        shadow_args.append(arg)
                        i += 1
                
                shadow_scr.write(" ".join(shadow_args) + "\n")
                shadow_scr.write("rm -f /tmp/httpreqr.pid || sudo rm -f /tmp/httpreqr.pid \n")
            
            os.chmod(shadow_scr_fn, mode=0o774)
            print(f"[WitcherAFL] Created shadow fuzzer script: {shadow_scr_fn}")
            print(f"[WitcherAFL] Shadow fuzzer work directory: {shadow_work_dir}")
            print(f"[WitcherAFL] Shadow fuzzer target: {secondary_url}")


        l.info(f"Fuzz command written out to {scr_fn}")
        os.chmod(scr_fn, mode=0o774)

        with open(logpath, "w") as fp:
            if self.container_info and self.container_info.get("name",None):
                most_recent_index = len(self.container_targets) - 1
                run_cmd = [scr_fn]
                print(f"{run_cmd}")

                proc = self.container_targets[most_recent_index].run_command(run_cmd, stdout=fp, stderr=fp)

                # Start shadow fuzzer if dual URL mode is enabled
                if shadow_scr_fn:
                    shadow_logpath = os.path.join(self.work_dir, f"{fuzzer_id}-shadow.log")
                    with open(shadow_logpath, "w") as shadow_fp:
                        shadow_run_cmd = [shadow_scr_fn]
                        print(f"[WitcherAFL] Starting shadow fuzzer: {shadow_run_cmd}")
                        shadow_proc = self.container_targets[most_recent_index].run_command(shadow_run_cmd, stdout=shadow_fp, stderr=shadow_fp)

                time.sleep(1)

                if proc.returncode and proc.returncode != 0:
                    # import ipdb
                    # ipdb.set_trace()
                    raise Exception("Error fuzzer failed to start")

                return proc

            else:
                main_proc = subprocess.Popen([scr_fn], stdout=fp, stderr=fp, close_fds=True)
                
                # Start shadow fuzzer if dual URL mode is enabled
                if shadow_scr_fn:
                    shadow_logpath = os.path.join(self.work_dir, f"{fuzzer_id}-shadow.log")
                    with open(shadow_logpath, "w") as shadow_fp:
                        print(f"[WitcherAFL] Starting shadow fuzzer: {shadow_scr_fn}")
                        shadow_proc = subprocess.Popen([shadow_scr_fn], stdout=shadow_fp, stderr=shadow_fp, close_fds=True)
                        print(f"[WitcherAFL] Shadow fuzzer PID: {shadow_proc.pid}")
                
                return main_proc

        # with open(logpath, "w") as fp:
        #     return subprocess.Popen(final_args, stdout=fp, stderr=fp, close_fds=True, env=my_env)

    @staticmethod
    def _check_for_authorized_response(body, headers, loginconfig):
        return WitcherAFL._check_body(body, loginconfig) and WitcherAFL._check_headers(headers, loginconfig)

    @staticmethod
    def _check_body(body, loginconfig):
        try:
            body = body.decode(errors='ignore')
        except (UnicodeDecodeError, AttributeError):
            pass
        if "positiveBody" in loginconfig and len(loginconfig["positiveBody"]) > 1:
            positive_body = loginconfig["positiveBody"]
            pattern = re.compile(positive_body)
            res = pattern.search(body)
            test = res is not None
            print(f"\033[36mChecking positiveBody pattern: '{positive_body}' -> {'FOUND' if test else 'NOT FOUND'}\033[0m")
            if not test and body:
                # Print first 200 chars of body for debugging
                body_preview = body[:200] + ("..." if len(body) > 200 else "")
                print(f"\033[33mResponse body preview: {body_preview}\033[0m")
            return test
        return True

    @staticmethod
    def _check_headers(headers, loginconfig):

        if "positiveHeaders" in loginconfig:
            posHeaders = loginconfig.get("positiveHeaders",{})
            print("posHeaders: ", posHeaders)
            print("headers: ", headers)
            for posname, posvalue in posHeaders.items():
                found = False
                for headername, headervalue in headers:
                    if posname == headername and posvalue in headervalue:
                        found = True
                        break
                if not found:
                    return False
        return True

    def _contains_session_cookie(self, session_cookie, loginconfig):

        session_name = loginconfig.get("loginSessionCookie",".*")
        if len(session_name) == "":
            session_name = ".*"

        # import ipdb
        # ipdb.set_trace()
        sessidrex = re.compile(rf"({session_name})=(?P<sessid>[a-z0-9_\-A-Z\%]{{24,256}})")


        session_match = sessidrex.match(session_cookie)
        if not session_match:
            return None

        sessid = session_match.group("sessid")
        print(f"COOKIE seen is {sessid}")
        return sessid

    def _save_session_data(self, loginconfig, sessid):
        session_cookie_locations = ["/tmp", "/var/lib/php/sessions"]
        if "cookieLocations" in loginconfig:
            for cl in loginconfig["cookeLocations"]:
                session_cookie_locations.append(cl)

        actual_sess_fn = ""
        for f in session_cookie_locations:

            sfile = f"*{sessid}"
            sesmask = os.path.join(f,sfile)
            for sfn in glob.glob(sesmask):
                if os.path.isfile(sfn):
                    actual_sess_fn = sfn
                    break
            if len(actual_sess_fn) > 0:
                break

        if len(actual_sess_fn) == 0:
            return True

        saved_sess_fn = f"/tmp/save_{sessid}"
        if os.path.isfile(actual_sess_fn):
            shutil.copyfile(actual_sess_fn, saved_sess_fn)
            os.chmod(saved_sess_fn, stat.S_IRWXO | stat.S_IRWXG | stat.S_IRWXU)
            self.used_sessions.add(saved_sess_fn)
            return True
        return True

    def _extract_authdata(self, headers, loginconfig):
        authdata = []
        login_auth_cookies = []
        for headername, headervalue in headers:
            if headername.upper() == "SET-COOKIE":
                # Uses special authdata header so that the value prepends all other cookie values and
                # random data from AFL does not interfere
                login_auth_cookies.append(headervalue)
                # cookie_dat = self._contains_session_cookie(headervalue, loginconfig)
                # if sessid:
                #     authdata.append(("LOGIN_COOKIE", headervalue))
                #     self._save_session_data(headervalue, loginconfig)


            if headername.upper() == "AUTHORIZATION":
                self.bearer = [(headername, headervalue)]
                authdata.append((headername, headervalue))

        if login_auth_cookies:
            login_auth_cookies_dict = {}
            for cookie in login_auth_cookies:
                items = cookie.split(";")
                for item in items:
                    if "=" in item:
                        key, value = item.split("=")
                        login_auth_cookies_dict[key] = value
            login_auth_cookies = [f"{k}={v}" for k, v in login_auth_cookies_dict.items()]
            print("login_auth_cookies: ", login_auth_cookies)
            authdata.append(("LOGIN_COOKIE",";".join(login_auth_cookies)))

        return authdata

    def _do_local_cgi_req_login(self, loginconfig):
        print("LOCAL CGI LOGIN")
        login_cmd = [loginconfig["cgiBinary"]]

        # print("[WC] \033[34m starting with command " + str(login_cmd) + "\033[0m")
        myenv = os.environ.copy()
        if "AFL_BASE" in myenv:
            del myenv["AFL_BASE"]

        myenv["METHOD"] = loginconfig["method"]
        if self.fault_escalation:
            myenv["STRICT"] = "3"
        elif "STRICT" in myenv:
            del myenv["STRICT"]
        myenv["SCRIPT_FILENAME"] = loginconfig["url"]
        myenv["SCRIPT_NAME"] = loginconfig["url"]
        if myenv["SCRIPT_NAME"].startswith("/app"):
            myenv["SCRIPT_NAME"] = myenv["SCRIPT_NAME"].replace("/app","")

        print(f"SCRIPT_NAME = {myenv['SCRIPT_NAME']}")

        if "afl_preload" in loginconfig:
            myenv["LD_PRELOAD"] = loginconfig["afl_preload"]
        if "ld_library_path" in loginconfig:
            myenv["LD_LIBRARY_PATH"] = loginconfig["ld_library_path"]

        extra_form_data = ""
        cookieData = ""
        if "preLoginPage" in loginconfig:

            pl_env = myenv.copy()
            pl_env["SCRIPT_FILENAME"] = loginconfig["preLoginPage"]
            pl_env["SCRIPT_NAME"] = loginconfig["preLoginPage"]

            if pl_env["SCRIPT_NAME"].startswith("/app"):
                pl_env["SCRIPT_NAME"] = pl_env["SCRIPT_NAME"].replace("/app", "")

            pl_env["METHOD"] = "GET"
            with open("/tmp/simple.inp","wb") as wf:
                wf.write(b"\x00\x00\x00")
            infile = open("/tmp/simple.inp", "rb")

            p = subprocess.Popen(login_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=infile, env=pl_env, close_fds=True)

            stdout, stderr = p.communicate(timeout=5)
            stdout = stdout.decode('latin-1')
            print(stdout)
            print("\n\n")
            rx = re.compile(r"Set-Cookie: ([\S]+=[\S]*)(.*)")

            match = rx.search(stdout)
            if match:
                cookieData = match.group(1)
                if cookieData[-1] == "\r":
                    cookieData = cookieData[:-1]

            print(f"Pre login cookies = {cookieData}, preloginPage={loginconfig['preLoginPage']}")

            rx = re.compile(r"(formid).*([a-f0-9]{32})")
            match = rx.search(stdout)
            if match:
                extra_form_data = f"{match.group(1)}={match.group(2)}"

        else:
            cookieData = loginconfig["cookieData"] if "cookieData" in loginconfig else ""


        getData = loginconfig["getData"] if "getData" in loginconfig else ""
        postData = loginconfig["postData"] if "postData" in loginconfig else ""

        if len(getData) > len(postData):
            getData += "&" + extra_form_data
        else:
            if len(extra_form_data) > 0:
                postData += "&" + extra_form_data
        print(f"cookiedData2={cookieData}")
        # Handle redirects manually with cookie propagation for CGI
        max_redirects = 3
        redirect_count = 0
        current_script = loginconfig["url"]
        current_method = loginconfig["method"]
        current_getData = getData
        current_postData = postData
        current_cookieData = cookieData
        current_cookies = {}
        final_headers = []
        final_body = ""
        
        # Parse initial cookies into dictionary
        if current_cookieData:
            for cookie_part in current_cookieData.split(";"):
                cookie_part = cookie_part.strip()
                if '=' in cookie_part:
                    cookie_name, cookie_value = cookie_part.split('=', 1)
                    current_cookies[cookie_name] = cookie_value
        
        while redirect_count < max_redirects:
            print(f"\033[36mCGI Request #{redirect_count + 1} to: {current_script}\033[0m")
            print(f"Method: {current_method}, GET Data: {current_getData}, POST Data: {current_postData}")
            
            # Update environment for current request
            myenv["SCRIPT_FILENAME"] = current_script
            myenv["SCRIPT_NAME"] = current_script
            if myenv["SCRIPT_NAME"].startswith("/app"):
                myenv["SCRIPT_NAME"] = myenv["SCRIPT_NAME"].replace("/app","")
            myenv["METHOD"] = current_method
            
            # Reconstruct cookie data from current cookies
            if current_cookies:
                current_cookieData = "; ".join([f"{name}={value}" for name, value in current_cookies.items()])
                print(f"\033[33mUsing cookies: {current_cookieData}\033[0m")
            else:
                current_cookieData = ""
            
            httpdata = f'{current_cookieData}\x00{current_getData}\x00{current_postData}\x00'

            with open("/tmp/login_req.dat", "wb") as wf:
                wf.write(httpdata.encode())

            env_str = ""
            for k, v in myenv.items():
                if k in "LD_LIBRARY_PATH,DOCUMENT_ROOT,AFL_SET_AFFINITY,SERVER_NAME,STRICT,WC_INSTRUMENTATION,NO_WC_EXTRA,SCRIPT_FILENAME,METHOD,SCRIPT_NAME":
                    env_str += f"export {k}='{v}';"
            print(f"\033[33m{' '.join(login_cmd)}\n{env_str}\033[0m")

            login_req_file = open("/tmp/login_req.dat", "r")

            p = subprocess.Popen(login_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=login_req_file, env=myenv)

            strout, stderr = p.communicate()
            login_req_file.close()

            if stderr:
                print(f"stderr = {stderr}")
            byteout = strout
            strout = strout.decode('latin-1')

            headers = []
            body = ""
            inbody = False
            #start = False
            extra_wait = False
            for respline in strout.splitlines():
                # if "END webcam_trace_init" in respline:
                #     start = True
                #     continue
                if respline.find("@@@@@@@@@@@@@") > -1:
                    extra_wait = True 
                if len(respline) == 0:# and start:
                    if extra_wait:
                        extra_wait=False
                        continue
                    inbody = True
                    continue
                if inbody:
                    body += respline + "\n"
                else:
                    header = respline.split(":")
                    if len(header) > 1:
                        headername = header[0].strip()
                        headerval = ":".join(header[1:])
                        headerval = headerval.lstrip()
                        headers.append((headername, headerval))
            
            final_headers = headers
            final_body = body
            
            # Check for redirect and extract cookies
            status_code = None
            location = None
            
            for headername, headerval in headers:
                if headername.lower() == "status":
                    try:
                        status_code = int(headerval.split()[0])
                    except (ValueError, IndexError):
                        pass
                elif headername.lower() == "location":
                    location = headerval
                elif headername.lower() == "set-cookie":
                    # Extract cookie name=value part
                    cookie_part = headerval.split(';')[0].strip()
                    if '=' in cookie_part:
                        cookie_name, cookie_value = cookie_part.split('=', 1)
                        current_cookies[cookie_name] = cookie_value
                        print(f"\033[33mAdded CGI cookie: {cookie_name}={cookie_value}\033[0m")
            
            print(f"\033[36mCGI Response status: {status_code or 'unknown'}\033[0m")
            if current_cookies:
                print(f"\033[33mCurrent CGI cookies: {current_cookies}\033[0m")
            
            # Check if it's a redirect
            if status_code and 300 <= status_code < 400 and location:
                print(f"\033[36mCGI redirecting to: {location}\033[0m")
                
                # Handle different types of location headers
                if location.startswith("http://SCRIPT/") or location.startswith("https://SCRIPT/"):
                    # Convert SCRIPT-based location to file path
                    new_path = location.replace("http://SCRIPT", "").replace("https://SCRIPT", "")
                    if new_path.startswith("/app/"):
                        current_script = new_path
                    else:
                        current_script = "/app" + new_path
                elif location.startswith("http://") or location.startswith("https://"):
                    # Full URL - extract path portion
                    from urllib.parse import urlparse
                    parsed = urlparse(location)
                    if parsed.path.startswith("/app/"):
                        current_script = parsed.path
                    else:
                        current_script = "/app" + parsed.path
                    
                    # Parse query parameters
                    if parsed.query:
                        current_getData = parsed.query
                    else:
                        current_getData = ""
                elif location.startswith("/"):
                    # Absolute path
                    if location.startswith("/app/"):
                        current_script = location
                    else:
                        current_script = "/app" + location
                else:
                    current_dir = os.path.dirname(current_script)
                    current_script = os.path.join(current_dir, location).replace("\\", "/")
                
                print(f"\033[36mResolved CGI script path: {current_script}\033[0m")
                
                redirect_count += 1
                
                # For redirects, switch to GET method and clear POST data
                current_method = "GET"
                current_postData = ""
                print(f"\033[36mSwitching to GET method for CGI redirect\033[0m")
                
                continue
            else:
                # Not a redirect, we're done
                print(f"\033[32mFinal CGI response received after {redirect_count} redirects\033[0m")
                break
        
        if redirect_count >= max_redirects:
            print(f"\033[31mWarning: Maximum CGI redirects ({max_redirects}) reached\033[0m")
        
        if not self._check_for_authorized_response(final_body, final_headers, loginconfig):
            print("\033[31mFailed to get authorization\033[0m")
            print(f"Final CGI Script = {current_script}")
            print(f"Final CGI Cookies = {current_cookies}")
            print(f"headers={final_headers}")
            print(f"body={final_body}")
            #print(f"strout={byteout}")
            exit(33)
            #raise Exception("Failed to get authorization")
            #return []

        # Use collected cookies from redirect process as auth data if available  
        if current_cookies:
            cookie_header = "; ".join([f"{name}={value}" for name, value in current_cookies.items()])
            authdata = [("LOGIN_COOKIE", cookie_header)]
            print(f"[*] Using collected CGI cookies as auth data: {cookie_header}")
            return authdata
        else:
            authdata = self._extract_authdata(final_headers, loginconfig)
            return authdata

    def _do_httpreqr_login(self, loginconfig, ipaddress=None, relogging=False):
        print("HTTP REQR LOGIN")
        url = loginconfig["url"]
        url = url.replace("@@PORT_INCREMENT@@", str(18080))

        if "getData" in loginconfig and loginconfig['getData']:
            url += f"?{loginconfig['getData']}"

        # if ipaddress:
        #     url = url.replace("127.0.0.1", ipaddress)

        post_data = loginconfig["postData"] if "postData" in loginconfig else ""
        post_data = post_data.encode('ascii')

        req_headers = loginconfig["headers"] if "headers" in loginconfig else {}
        method = loginconfig.get("method","GET")

        #opener = urllib.request.build_opener(NoRedirection)
        #urllib.request.install_opener(opener)

        #req = urllib.request.Request(url, post_data, req_headers, method=method)

        #response = urllib.request.urlopen(req)
        #headers = response.getheaders()
        #body = response.read()

        for t in self.container_targets:

            p = t.run_command(["/httpreqr","--url",url], env=["AFL_META_INFO_ID=80"])
            stdout, stderr = p.communicate(input=b'\x00\x00' + post_data + b'\x00')

            body = stdout.decode('latin-1')
            headers = body
            if not WitcherAFL._check_for_authorized_response(body, headers, loginconfig):
                print("[Witcher] \033[31mFAILED to get AUTHORIZATION\033[0m")
                print(f"\tURL = {url}")
                print(f"\tresponse={body}")
                if not relogging:
                    exit(33)

    @staticmethod
    def _do_http_req_login(loginconfig, ipaddress=None, relogging=False):
        print("HTTP REQ LOGIN")
        url = loginconfig["url"]
        url = url.replace("@@PORT_INCREMENT@@", str(18080))

        if "getData" in loginconfig and loginconfig['getData']:
            url += f"?{loginconfig['getData']}"

        if ipaddress:
            url = url.replace("127.0.0.1", ipaddress)

        post_data = loginconfig["postData"] if "postData" in loginconfig else ""
        original_post_data = post_data
        post_data = post_data.encode('ascii')

        req_headers = loginconfig["headers"] if "headers" in loginconfig else {}
        original_method = loginconfig.get("method", "GET")
        method = original_method
        
        # Handle redirects manually with cookie propagation
        max_redirects = 3
        redirect_count = 0
        current_url = url
        current_cookies = {}
        final_headers = []
        final_body = b""
        
        opener = urllib.request.build_opener(NoRedirection)
        urllib.request.install_opener(opener)
        
        while redirect_count < max_redirects:
            print(f"\033[36mHTTP Request #{redirect_count + 1} to: {current_url}\033[0m")
            print(f"Method: {method}, Post Data: {post_data}")
            
            # Create request with current cookies
            current_req_headers = req_headers.copy()
            if current_cookies:
                cookie_header = "; ".join([f"{name}={value}" for name, value in current_cookies.items()])
                current_req_headers["Cookie"] = cookie_header
                print(f"\033[33mUsing cookies: {cookie_header}\033[0m")
            
            print(f"headers={current_req_headers}")
            req = urllib.request.Request(current_url, post_data, current_req_headers, method=method)

            try:
                response = urllib.request.urlopen(req)
                headers = response.getheaders()
                body = response.read()
                status_code = response.getcode()
                
                print(f"\033[36mResponse code: {status_code}\033[0m")
                
                # Accumulate cookies from response (keep all previous cookies)
                for header_name, header_value in headers:
                    if header_name.lower() == "set-cookie":
                        cookie_part = header_value.split(';')[0].strip()
                        if '=' in cookie_part:
                            cookie_name, cookie_value = cookie_part.split('=', 1)
                            current_cookies[cookie_name] = cookie_value
                #             print(f"\033[33mAdded cookie: {cookie_name}={cookie_value}\033[0m")
                # print(f"\033[33mAll cookies so far: {current_cookies}\033[0m")
                
                final_headers = headers
                final_body = body
                
                # Check if it's a redirect (3xx status codes)
                if 300 <= status_code < 400:
                    location = None
                    for header_name, header_value in headers:
                        if header_name.lower() == "location":
                            location = header_value
                            break
                    
                    if location:
                        print(f"\033[36mRedirecting to: {location}\033[0m")
                        
                        # Handle relative URLs
                        if location.startswith('/'):
                            from urllib.parse import urlparse, urlunparse
                            parsed_current = urlparse(current_url)
                            location = urlunparse((parsed_current.scheme, parsed_current.netloc, location, '', '', ''))
                        elif not location.startswith('http'):
                            from urllib.parse import urljoin
                            location = urljoin(current_url, location)
                        
                        current_url = location
                        redirect_count += 1
                        
                        # For redirects, switch to GET method and clear POST data
                        method = "GET"
                        post_data = b""
                        print(f"\033[36mSwitching to GET method for redirect\033[0m")
                        
                        continue
                    else:
                        print(f"\033[31mWarning: Got redirect status {status_code} but no Location header\033[0m")
                        break
                else:
                    # Not a redirect, we're done
                    print(f"\033[32mFinal response received after {redirect_count} redirects\033[0m")
                    break
                    
            except urllib.error.HTTPError as e:
                print(f"\033[31mHTTP Error {e.code}: {e.reason}\033[0m")
                final_headers = e.headers.items() if hasattr(e.headers, 'items') else []
                final_body = e.read() if hasattr(e, 'read') else b""
                
                # Accumulate cookies even from error responses (keep all previous cookies)
                for header_name, header_value in final_headers:
                    if header_name.lower() == "set-cookie":
                        cookie_part = header_value.split(';')[0].strip()
                        if '=' in cookie_part:
                            cookie_name, cookie_value = cookie_part.split('=', 1)
                            current_cookies[cookie_name] = cookie_value
                            print(f"\033[33mAdded cookie from error: {cookie_name}={cookie_value}\033[0m")
                print(f"\033[33mAll cookies after error: {current_cookies}\033[0m")
                
                # Check for redirects in error responses
                if 300 <= e.code < 400:
                    location = None
                    for header_name, header_value in final_headers:
                        if header_name.lower() == "location":
                            location = header_value
                            break
                    
                    if location:
                        print(f"\033[36mRedirecting from error to: {location}\033[0m")
                        if location.startswith('/'):
                            from urllib.parse import urlparse, urlunparse
                            parsed_current = urlparse(current_url)
                            location = urlunparse((parsed_current.scheme, parsed_current.netloc, location, '', '', ''))
                        elif not location.startswith('http'):
                            from urllib.parse import urljoin
                            location = urljoin(current_url, location)
                        
                        current_url = location
                        redirect_count += 1
                        
                        # Switch to GET for redirect
                        method = "GET"  
                        post_data = b""
                        print(f"\033[36mSwitching to GET method for error redirect\033[0m")
                        
                        continue
                
                # If not a redirect error, break
                break
                
            except Exception as e:
                print(f"\033[31mError during HTTP request: {e}\033[0m")
                raise
        
        if redirect_count >= max_redirects:
            print(f"\033[31mWarning: Maximum redirects ({max_redirects}) reached\033[0m")

        # ipdb.set_trace()

        if not WitcherAFL._check_for_authorized_response(final_body, final_headers, loginconfig):
            print("[Witcher] \033[31mFAILED to get AUTHORIZATION\033[0m")
            print(f"\tFinal URL = {current_url}")
            print(f"\tFinal Cookies = {current_cookies}")
            #print(f"\tresponse={final_body}")
            print(f"\tresponse={status_code if 'status_code' in locals() else 'unknown'}")
            print(f"\tresponse={final_headers}")
            if not relogging:
                raise Exception("Failed to get authorization")

        return final_body, final_headers, current_cookies

    @staticmethod
    def _do_authorized_requests(loginconfig, authdata):
        extra_requests = loginconfig["extra_authorized_requests"] if "postData" in loginconfig else []

        for auth_request in extra_requests:

            url = auth_request["url"]
            if not url:
                continue

            if "getData" in auth_request:
                url += f"?{auth_request['getData']}"

            post_data = auth_request["postData"] if "postData" in auth_request else ""
            post_data = post_data.encode('ascii')

            req_headers = auth_request["headers"] if "headers" in auth_request else {}
            for adname, advalue in authdata:
                adname = adname.replace("LOGIN_COOKIE","Cookie")
                req_headers[adname] = advalue
                
            req = urllib.request.Request(url, post_data, req_headers)
            urllib.request.urlopen(req)

    def _get_login(self, my_env, ipaddress=None):

        if self.login_json_fn == "":
            return

        if len(self.bearer) > 0:
            for bname, bvalue in self.bearer:
                my_env[bname] = bvalue
            return

        with open(self.login_json_fn, "r") as jfile:
            jdata = json.load(jfile)
        if jdata["direct"]["url"] == "NO_LOGIN":
            return
        loginconfig = jdata["direct"]
        if not loginconfig["url"]:
            return

        saved_session_id = self._get_saved_session()
        #my_env["LOGIN_COOKIE"]="csrftoken=aaa; password=bbb"
        if len(saved_session_id) > 0:
            saved_session_name = loginconfig["loginSessionCookie"]
            my_env["LOGIN_COOKIE"] = f"{saved_session_name}:{saved_session_id}"
            return

        authdata = None
        while True:
            if loginconfig["url"].startswith("http"):
                try:
                    final_body, final_headers, collected_cookies = WitcherAFL._do_http_req_login(loginconfig, ipaddress)
                except Exception as e:
                    print(f"{e} while trying to login, retrying...")
                    time.sleep(5)
                    continue

                # Use collected cookies from redirect process as auth data if available
                if collected_cookies:
                    cookie_header = "; ".join([f"{name}={value}" for name, value in collected_cookies.items()])
                    authdata = [("LOGIN_COOKIE", cookie_header)]
                    print(f"[*] Using collected cookies as auth data: {cookie_header}")
                else:
                    authdata = self._extract_authdata(final_headers, loginconfig)

                if self.relog:
                    p = Process(target=self._do_relog, args=(loginconfig, ipaddress, self.running_flag))
                    p.start()
                    print("[Witcher] Started relog process")
                    self.relog_process = p

                print(f"[*] Authorized data = {authdata}")
                WitcherAFL._do_authorized_requests(loginconfig, authdata)
            else:
                authdata = self._do_local_cgi_req_login(loginconfig)
                print(f"[*] Authorized data = {authdata}")
            if authdata is not None:
                break
            time.sleep(5)

        if authdata is None:
            raise ValueError("Login failed to return authenticated cookie/bearer value")
        for authname, authvalue in authdata:
            my_env[authname] = authvalue

    def _do_relog(self, loginconfig, ipaddress, running_flag):
        while running_flag:
            self._do_httpreqr_login(loginconfig, ipaddress, relogging=True)
            time.sleep(30)

    def _get_saved_session(self):
        # if we have an unused session file, we are done for this worker.
        for saved_sess_fn in glob.iglob("/tmp/save_????????????????????*"):
            if saved_sess_fn not in self.used_sessions:
                sess_fn = saved_sess_fn.replace("save", "sess")
                print("sess_fn=" + sess_fn)
                self.used_sessions.add(saved_sess_fn)
                shutil.copyfile(saved_sess_fn, sess_fn)

                saved_session_id = saved_sess_fn.split("_")[1]
                return saved_session_id
        return ""

    def stop(self):
        self.running_flag = False
        super().stop()


class NoRedirection(urllib.request.HTTPErrorProcessor):

    def http_response(self, request, response):
        return response

    https_response = http_response


class NonBlockingStreamReader:

    def __init__(self, stream):
        '''
        stream: the stream to read from.
                Usually a process' stdout or stderr.
        '''

        self._s = stream
        self._q = Queue()
        self._finished = False

        def _populateQueue(stream, queue):
            '''
            Collect lines from 'stream' and put them in 'quque'.
            '''

            while True:
                line = stream.readline()
                if line:
                    queue.put(line)
                else:
                    self._finished = True
                    #raise UnexpectedEndOfStream

        self._t = Thread(target = _populateQueue,
                         args = (self._s, self._q))
        self._t.daemon = True
        self._t.start() #start collecting lines from the stream

    @property
    def is_finished(self):
        return self._finished

    def readline(self, timeout = None):
        try:
            if self._finished:
                return None
            return self._q.get(block = timeout is not None,
                    timeout = timeout)
        except Empty:
            return None


class UnexpectedEndOfStream(Exception):
    pass
