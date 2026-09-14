from __future__ import annotations

try:
    from . import run_review as base
except ImportError:
    import run_review as base

_prepare_observation = None
_prepare_evidence: set[str] = set()
_original_contained_entrypoint = base.contained_entrypoint
_original_write_result = base.write_result


def contained_entrypoint_with_prepare(req):
    global _prepare_observation, _prepare_evidence
    _prepare_evidence = set(req.evidence)
    if req.prepare_profile == "npm_build":
        before = base.snapshot(base.WORKSPACE) if "filesystem" in _prepare_evidence else {}
        rc, out, err = base.run_bounded(
            ["npm", "run", "build"],
            "PREPARE",
            base.PHASE_LIMITS["INSTALL"],
            trace=bool(_prepare_evidence & {"network", "process"}),
            stop_on_output_limit="output_capture_limit" in req.stop_conditions,
        )
        if rc:
            raise base.TargetFailure("Target preparation failed: " + base.sanitize(err or out))
        if "filesystem" in _prepare_evidence:
            after = base.snapshot(base.WORKSPACE)
            _prepare_observation = base.filesystem_observation(before, after, "PREPARE")
    return _original_contained_entrypoint(req)


def write_result_with_prepare(path, result):
    profile = result.get("request", {}).get("prepare_profile", "NONE")
    provenance = result.setdefault("provenance", {})
    provenance["prepare_profile"] = profile
    if profile == "npm_build":
        prepare_failed = any(
            error.get("message", "").startswith("Target preparation failed:")
            for error in result.get("errors", [])
        )
        provenance["prepare_status"] = "FAILED" if prepare_failed else "COMPLETED"
        if _prepare_observation is not None:
            prepare_paths = set(_prepare_observation["data"]["paths"])
            result.setdefault("observations", []).append(_prepare_observation)
            for item in result.get("observations", []):
                if item.get("type") == "filesystem_changes" and item.get("phase") == "EXERCISE":
                    item["data"]["paths"] = [p for p in item["data"]["paths"] if p not in prepare_paths]
        result.setdefault("observations", []).extend(base.parse_traces(["PREPARE"], _prepare_evidence))
    else:
        provenance["prepare_status"] = "NOT_REQUESTED"
    _original_write_result(path, result)


base.contained_entrypoint = contained_entrypoint_with_prepare
base.write_result = write_result_with_prepare


if __name__ == "__main__":
    raise SystemExit(base.main())
