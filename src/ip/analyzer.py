from concurrent.futures import ThreadPoolExecutor

from src.ip.classifier import classify
from src.ip.lookup import RdapError, lookup_rdap, reverse_dns
from src.ip.models import AddressEntry, IPAnalysis

MAX_WORKERS = 4

NO_PTR_CATEGORIES = frozenset({
    "unspecified",
    "broadcast",
    "multicast",
})


def analyze_address(
    entry: AddressEntry,
    known_ips: set[str] | None,
    resolve: bool,
    rdap: bool,
    timeout: float,
) -> IPAnalysis:
    analysis = IPAnalysis(
        input=entry.raw,
        sources=list(entry.sources),
        context=entry.context,
    )

    try:
        classification = classify(entry.raw)
    except ValueError as error:
        analysis.error = str(error)
        return analysis

    analysis.classification = classification

    if known_ips is not None:
        analysis.approved = classification.address in known_ips

    if resolve:
        if classification.category in NO_PTR_CATEGORIES:
            analysis.lookup_messages["dns"] = (
                "Skipped: reverse DNS does not apply to this "
                "address type."
            )
        else:
            hostname, message = reverse_dns(
                classification.address,
                timeout,
            )

            analysis.hostname = hostname

            if message:
                analysis.lookup_messages["dns"] = message

    if rdap:
        if not classification.is_global:
            analysis.lookup_messages["rdap"] = (
                "Skipped: not a globally routable address."
            )
        else:
            try:
                analysis.rdap = lookup_rdap(
                    classification.address,
                    timeout,
                )
            except RdapError as error:
                analysis.lookup_messages["rdap"] = str(error)

    return analysis


def analyze_addresses(
    entries: list[AddressEntry],
    known_ips: set[str] | None,
    resolve: bool,
    rdap: bool,
    timeout: float,
) -> list[IPAnalysis]:
    def run(entry: AddressEntry) -> IPAnalysis:
        return analyze_address(
            entry,
            known_ips,
            resolve,
            rdap,
            timeout,
        )

    if not (resolve or rdap) or len(entries) < 2:
        return [run(entry) for entry in entries]

    with ThreadPoolExecutor(
        max_workers=min(MAX_WORKERS, len(entries))
    ) as executor:
        return list(executor.map(run, entries))