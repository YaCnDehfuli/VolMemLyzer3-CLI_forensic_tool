from .extractors import *
from .extractors import _legacy_adapter
from .core import PluginSpec
from .extractor_registry import ExtractorRegistry


def spec(name, func, *, deps=(), timeout=None, at=(), cost="fast"):
    """One row of the plugin table.

    `at` lists the fully-qualified Volatility names for this plugin, most current
    first. Volatility resolves what you type by substring, so a bare
    "windows.<name>" usually works -- but it breaks in two ways worth naming
    explicitly. Plugins get relocated (malfind, psxview, ldrmodules, drivermodule
    and skeleton_key_check now live under windows.malware.*, amcache and
    scheduled_tasks under windows.registry.*) and the old module survives only as
    a shim with a removal date on it. And "windows.windows" is a substring of
    "windows.windowstations", which Volatility rejects as ambiguous rather than
    guessing. Naming the target removes both problems.

    `cost` orders submission so the long jobs start first; see PluginSpec.
    """
    return (name, func, tuple(deps), timeout, tuple(at), cost)


PLUGIN_SPECIFICS = [
    spec("info",                 extract_winInfo_features,                 at=("windows.info.Info",)),
    spec("pslist",               extract_pslist_features,                  at=("windows.pslist.PsList",)),
    spec("psscan",               extract_psscan_features,                  deps=("pslist",), at=("windows.psscan.PsScan",), cost="scan"),
    spec("threads",              extract_threads_features,                 at=("windows.threads.Threads",), cost="scan"),
    spec("thrdscan",             extract_thrdscan_features,                deps=("threads",), at=("windows.thrdscan.ThrdScan",), cost="scan"),
    spec("deskscan",             extract_deskscan_features,                deps=("pslist",), at=("windows.deskscan.DeskScan",), cost="scan"),
    spec("amcache",              extract_amcache_features,                 deps=("info",), at=("windows.registry.amcache.Amcache", "windows.amcache.Amcache")),

    spec("bigpools",             extract_bigpools_features,                at=("windows.bigpools.BigPools",), cost="scan"),
    spec("cmdline",              extract_cmdline_features,                 at=("windows.cmdline.CmdLine",)),
    spec("cmdscan",              extract_cmdscan_features,                 at=("windows.cmdscan.CmdScan",)),
    spec("consoles",             extract_consoles_features,                at=("windows.consoles.Consoles",)),
    spec("dlllist",              extract_dlllist_features,                 at=("windows.dlllist.DllList",), cost="scan"),
    spec("envars",               extract_envars_features,                  at=("windows.envars.Envars",)),
    spec("getservicesids",       extract_getservicesids_features,          at=("windows.getservicesids.GetServiceSIDs",)),
    spec("getsids",              extract_getsids_features,                 at=("windows.getsids.GetSIDs",)),
    spec("handles",              extract_handles_features,                 at=("windows.handles.Handles",), cost="heavy"),
    spec("iat",                  extract_iat_features,                     at=("windows.iat.IAT",), cost="heavy"),
    spec("joblinks",             extract_joblinks_features,                at=("windows.joblinks.JobLinks",)),
    spec("ldrmodules",           extract_ldrmodules_features,              at=("windows.malware.ldrmodules.LdrModules", "windows.ldrmodules.LdrModules"), cost="scan"),
    spec("malfind",              extract_malfind_features,                 at=("windows.malware.malfind.Malfind", "windows.malfind.Malfind"), cost="heavy"),
    spec("mbrscan",              extract_mbrscan_features,                 at=("windows.mbrscan.MBRScan",), cost="scan"),
    spec("modules",              extract_modules_features,                 at=("windows.modules.Modules",)),
    spec("netstat",              extract_netstat_features,                 at=("windows.netstat.NetStat",)),
    spec("privileges",           extract_privileges_features,              at=("windows.privileges.Privs",)),
    spec("pstree",               extract_pstree_features,                  at=("windows.pstree.PsTree",)),

    spec("registry.printkey",    extract_registry_printkey_features,       at=("windows.registry.printkey.PrintKey",)),
    spec("registry.hivelist",    extract_registry_hivelist_features,       at=("windows.registry.hivelist.HiveList",)),
    spec("registry.hivescan",    extract_registry_hivescan_features,       deps=("registry.hivelist",), at=("windows.registry.hivescan.HiveScan",), cost="scan"),
    spec("registry.certificates",extract_registry_certificates_features,   at=("windows.registry.certificates.Certificates",)),
    spec("registry.userassist",  extract_registry_userassist_features,     at=("windows.registry.userassist.UserAssist",)),

    spec("shimcache",            extract_shimcache_features,               at=("windows.shimcachemem.ShimcacheMem",), cost="scan"),
    spec("skeleton_key",         extract_skeleton_key_features,            at=("windows.malware.skeleton_key_check.Skeleton_Key_Check", "windows.skeleton_key_check.Skeleton_Key_Check")),
    spec("ssdt",                 extract_ssdt_features,                    at=("windows.ssdt.SSDT",)),
    spec("statistics",           extract_statistics_features,              at=("windows.statistics.Statistics",), cost="scan"),
    spec("svcscan",              extract_svcscan_features,                 at=("windows.svcscan.SvcScan",), cost="scan"),
    spec("svclist",              extract_svclist_features,                 at=("windows.svclist.SvcList",)),
    spec("timers",               extract_timers_features,                  at=("windows.timers.Timers",)),

    spec("vadinfo",              extract_vadinfo_features,                 at=("windows.vadinfo.VadInfo",), cost="heavy"),
    spec("vadwalk",              extract_vadwalk_features,                 at=("windows.vadwalk.VadWalk",), cost="scan"),
    spec("verinfo",              extract_verinfo_features,                 at=("windows.verinfo.VerInfo",), cost="heavy"),
    spec("virtmap",              extract_virtmap_features,                 at=("windows.virtmap.VirtMap",), cost="scan"),
    spec("windows",              extract_windows_features,                 at=("windows.windows.Windows",)),
    spec("windowstations",       extract_windowstations_features,          at=("windows.windowstations.WindowStations",)),

    # Physical-layer scanners. Each one sweeps the whole image looking for pool
    # tags, so they dominate the wall clock and are submitted before anything else.
    spec("callbacks",            extract_callbacks_features,               at=("windows.callbacks.Callbacks",)),
    spec("devicetree",           extract_devicetree_features,              at=("windows.devicetree.DeviceTree",), cost="scan"),
    spec("driverirp",            extract_driverirp_features,               at=("windows.driverirp.DriverIrp",)),
    spec("drivermodule",         extract_drivermodule_features,            at=("windows.malware.drivermodule.DriverModule", "windows.drivermodule.DriverModule")),
    spec("driverscan",           extract_driverscan_features,              at=("windows.driverscan.DriverScan",), cost="scan"),
    spec("filescan",             extract_filescan_features,                at=("windows.filescan.FileScan",), cost="heavy"),
    spec("modscan",              extract_modscan_features,                 at=("windows.modscan.ModScan",), cost="scan"),
    spec("mutantscan",           extract_mutantscan_features,              at=("windows.mutantscan.MutantScan",), cost="scan"),
    spec("netscan",              extract_netscan_features,                 at=("windows.netscan.NetScan",), cost="scan"),
    spec("scheduled_tasks",      extract_scheduled_tasks_features,         at=("windows.registry.scheduled_tasks.ScheduledTasks", "windows.scheduled_tasks.ScheduledTasks")),
    spec("poolscanner",          extract_poolscanner_features,             at=("windows.poolscanner.PoolScanner",), cost="scan"),
    spec("symlinkscan",          extract_symlinkscan_features,             at=("windows.symlinkscan.SymlinkScan",), cost="scan"),
    # Re-runs psscan, thrdscan and a csrss handle sweep internally, so it costs
    # more than those plugins put together.
    spec("psxview",              extract_psxview_features,                 at=("windows.malware.psxview.PsXView", "windows.psxview.PsXView"), cost="heavy"),
]


def parse_entries(ent):
    name, func, deps, timeout, at, cost = ent
    lower = str(name).strip().lower()
    # Fallback only: used when we cannot ask Volatility what it has installed.
    fqname = at[0] if at else (lower if lower.startswith("windows.") else f"windows.{lower}")
    spec_obj = PluginSpec(name=lower, fqname=fqname, deps=tuple(deps), timeout_s=timeout,
                          candidates=tuple(at), cost=cost)
    return spec_obj, _legacy_adapter(func)


def build_registry() -> ExtractorRegistry:
    reg = ExtractorRegistry()
    for ent in PLUGIN_SPECIFICS:
        s, func = parse_entries(ent)
        reg.register(s, func)
    return reg
