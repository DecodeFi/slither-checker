#!/usr/bin/env pipenv-shebang

import json, subprocess, shutil, os, logging, sys, yaml, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from threading import Lock

logger = logging.getLogger('server_logger')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)

formatter = logging.Formatter('(thd=%(thread)d) [%(asctime)s] %(levelname)s: %(message)s')

ch.setFormatter(formatter)
logger.addHandler(ch)

def analyze(output_path):
    reports = dict()
    reasons = dict()
    
    backoff = 1
    while True:
        if os.path.isfile(output_path):
            break
        
        time.sleep(backoff)
        backoff *= 2
        logger.info(f"no {output_path}, sleep for {backoff}")
    
    with open(output_path, "r") as out:
        out_json = json.loads(out.read())
        if not out_json["success"]:
            result = {"reports" : out_json, "score": -1}
            return result
        
        reports = []
        if not "detectors" in out_json["results"]:
            result = {"reports": {}, "score": 0}
            return result

        for report in out_json["results"]["detectors"]:
            funcs, variables, lines = [], [], []
            skip = False

            for element in report["elements"]:
                if element["type"] == "function":
                    f = element["type_specific_fields"]["signature"]
                    funcs.append(f)
                elif element["type"] == "variable":
                    v = element["name"]
                    variables.append(v)
                elif element["type"] == "node":
                    l = element["source_mapping"]["lines"]
                    lines.extend(l)
            
            if skip:
                continue
            
            reports.append({
                "check" : report["check"],
                "impact": report["impact"],
                "confidence": report["confidence"],
                "functions": funcs,
                "variables" : variables,
                "lines": lines,
            })
            
            # collect all unqiue detectors, score them according to a) confidence b) impact c) our own estimate of "seriousness"
            # TODO!: formulas below are kinda random, we need to come up with more relyable method
            check_coeff = 1
            if report["check"] in scores["detector_scores"]:
                check_coeff = scores["detector_scores"][report["check"]]
            score = scores["score_table"][report["confidence"]][report["impact"]] * check_coeff
            reasons[report["check"]] = score

    # TODO!: formulas below are kinda random, we need to come up with more relyable method    
    score = 0
    for r in reasons:
        score += reasons[r]
    
    result = {"reports" : reports, "score": score}
    return result

# read address json, create source file-tree
def process(address_json):
    address = address_json["address"]
    if os.path.exists(address) and os.path.isdir(address):
        shutil.rmtree(address)
    
    if address_json["contract_source_code"] is None:
        result = {"reports" : {"reason": "no source code"}, "score": -3}
        return result
    
    compiler_version = address_json["compiler_version"]
    
    # HACKY! TODO: separate function for this!
    if compiler_version is None:
        compiler_version = "latest"
    else:
        compiler_version = compiler_version.split("+")[0][1:] 
    
    logger.info(f"address = {address}, compiler_version = {compiler_version}")
    
    try:
        sources_json = json.loads(address_json["contract_source_code"][1:-1])
    except:
        if address_json["contract_source_code"].find("pragma solidity") == -1:
            return {"reports" : {"reason": "malformed source code json"}, "score": -4}
        
        sources_json = {
            "sources": {
                "main.sol" : {
                    "content": address_json["contract_source_code"]
                }
            },
            "settings": {
                "outputSelection": { "*": { "*": [ "*" ], "": [ "*" ] } }
            }
        }
    
    sources_json["settings"]["outputSelection"] = { "*": { "*": [ "*" ], "": [ "*" ] } }
    
    source_paths = sources_json["sources"]
    targets = []
    for source_path in source_paths:
        path = f"./{address}/{source_path}"

        command = f"mkdir -p $(dirname '{path}') && touch '{path}'"
        subprocess.run(command, shell=True, check=True)

        with open(path, "w") as ww:
            ww.write(source_paths[source_path]["content"])
            targets.append(source_path)
    
    settings_path = f"./{address}/settings"
    with open(settings_path, "w") as sw:
        sw.write(json.dumps(sources_json))
        
    output = f"output.json"
    env = os.environ if os.environ is not None else dict()
    env["SOLC_VERSION"] = compiler_version
    
    ret = subprocess.run([
        "slither",
        "--exclude-informational", 
        "--exclude-optimization",
        "--json",  output,
        "--compile-force-framework", 'solc-json', "settings"
        ],
        env=env,
        capture_output=True,
        cwd = f"./{address}"
    )
    
    try:
        result = analyze(f"./{address}/output.json")
    except Exception as e:
        logger.error(e)
        result = {"reports" : {"slither.stdout": ret.stdout, "slither.stderr": ret.stderr}, "score": -2}
    
    return result


LOCKS = dict()
LOCKS_LOCK = Lock()

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        global LOCKS, LOCKS_LOCK
        
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length).decode('utf8')
        request = json.loads(body)
        
        logger.info("got POST request")
        
        with LOCKS_LOCK:
            if request["address"] not in LOCKS:
                LOCKS[request["address"]] = Lock()
        
        with LOCKS[request["address"]]:
            res = process(request)
            logger.info(f"address = {request['address']} score = {res['score']}")
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        response = BytesIO()
        response.write(bytes(json.dumps(res), "utf8"))
        self.wfile.write(response.getvalue())


if __name__ == "__main__":
        with open("scores.yaml", "r") as yamlfile:
            scores = yaml.load(yamlfile, Loader=yaml.FullLoader)
        httpd = ThreadingHTTPServer(('', 7777), RequestHandler)
        httpd.serve_forever()
