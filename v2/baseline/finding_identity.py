"""Compare OpenGrep JSON and SARIF primary findings without rewriting either artifact."""
from collections import Counter
from urllib.parse import unquote, urlsplit
import re


def path_key(value, uri=False):
    if not isinstance(value, str) or not value:
        raise ValueError("missing finding path/URI")
    if uri:
        if value.lower().startswith("file:"):
            parsed = urlsplit(value)
            if parsed.query or parsed.fragment:
                raise ValueError("ambiguous file URI")
            value = unquote(parsed.path)
            if parsed.netloc and parsed.netloc.lower() != "localhost":
                value = "//" + parsed.netloc + value
            if re.match(r"^/[A-Za-z]:/", value):
                value = value[1:]
        else:
            if "://" in value:
                raise ValueError("unsupported SARIF artifact URI scheme")
            value = unquote(value)
    value = value.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", value):
        value = value[0].lower() + value[1:]
    return value


def span(start_line, start_col, end_line, end_col):
    values = (start_line, start_col, end_line, end_col)
    if any(type(x) is not int or x < 1 for x in values):
        raise ValueError("finding needs explicit positive line/column coordinates")
    if end_line < start_line or (end_line == start_line and end_col < start_col):
        raise ValueError("reversed finding span")
    return values


def compare_findings(raw, sarif):
    if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
        raise ValueError("invalid OpenGrep results envelope")
    if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
        raise ValueError("invalid SARIF runs envelope")
    json_keys, sarif_keys = [], []
    for result in raw["results"]:
        if not isinstance(result, dict) or not isinstance(result.get("check_id"), str) or not result["check_id"]:
            raise ValueError("JSON finding missing rule ID")
        start, end = result.get("start"), result.get("end")
        if not isinstance(start, dict) or not isinstance(end, dict):
            raise ValueError("JSON finding missing span")
        json_keys.append((result["check_id"], path_key(result.get("path")),
                          *span(start.get("line"), start.get("col"), end.get("line"), end.get("col"))))
    for run in sarif["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            raise ValueError("SARIF run missing results")
        for result in run["results"]:
            if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str) or not result["ruleId"]:
                raise ValueError("SARIF finding missing explicit rule ID")
            locations = result.get("locations")
            if not isinstance(locations, list) or len(locations) != 1 or not isinstance(locations[0], dict):
                raise ValueError("SARIF finding needs one unambiguous primary location")
            physical = locations[0].get("physicalLocation")
            if not isinstance(physical, dict) or not isinstance(physical.get("region"), dict) or not isinstance(physical.get("artifactLocation"), dict):
                raise ValueError("SARIF finding missing physical location")
            region = physical["region"]
            sarif_keys.append((result["ruleId"], path_key(physical["artifactLocation"].get("uri"), uri=True),
                               *span(region.get("startLine"), region.get("startColumn"),
                                     region.get("endLine", region.get("startLine")), region.get("endColumn"))))
    if Counter(json_keys) != Counter(sarif_keys):
        raise ValueError("JSON/SARIF rule IDs or primary path/line/column spans differ (including multiplicity)")
    return {"findings": len(json_keys), "sarif_findings": len(sarif_keys), "rule_ids_and_locations_match": True}
