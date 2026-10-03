"""Mobile-only forensic services separated from Disk/EWF orchestration.

Android and iOS run in independent service processes, brokers and databases.
Only low-level evidence/image primitives are shared with Disk forensics.
"""

from app.services.mobile_forensic.detection import is_mobile_job, mobile_platform
from app.services.mobile_forensic.inventory import (
    build_mobile_inventory_snapshot,
    count_mobile_axiom_artifact,
)
from app.services.mobile_forensic.segments import is_mobile_segment_filename

__all__ = [
    "is_mobile_job",
    "mobile_platform",
    "count_mobile_axiom_artifact",
    "build_mobile_inventory_snapshot",
    "is_mobile_segment_filename",
]
