import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, Plus, Save, Trash2, UserPlus } from "lucide-react";
import { Button, Card, Field, Input, PageHeader, Select, Spinner } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import type {
  CaseSubjectInput,
  CaseTypeOption,
  CustomObjectiveInput,
  Intake,
  IntakePatch,
  ReportObjectiveOption,
  ReportTypeOption,
} from "../../lib/types/forensic";

const OBJECTIVE_TITLE_KEY = (title: string) =>
  title.trim().toLowerCase().replace(/&/g, "and").replace(/\s+/g, " ");

function dedupeObjectiveOptions(items: ReportObjectiveOption[]): ReportObjectiveOption[] {
  function score(item: ReportObjectiveOption): number {
    const proc = (item.procedure_text || item.procedure || "").trim();
    const numbered = proc.startsWith("1") ? 1_000_000 : 0;
    const legacy = item.id.toUpperCase().startsWith("RPT-") ? -1_000_000 : 0;
    return numbered + legacy + proc.length;
  }
  const byTitle = new Map<string, ReportObjectiveOption>();
  for (const item of items) {
    const key = OBJECTIVE_TITLE_KEY(item.title);
    const existing = byTitle.get(key);
    if (!existing || score(item) > score(existing)) {
      byTitle.set(key, item);
    }
  }
  return Array.from(byTitle.values());
}

const MISSING_LABEL: Record<string, string> = {
  subjects: "at least one subject (name + email)",
  case_type: "case type",
  report_type: "report type",
  objectives: "at least one objective",
};

function isMobileCaseType(caseType: string | null | undefined, reportType?: string | null): boolean {
  const ct = (caseType || "").trim().toLowerCase();
  const rt = (reportType || "").trim().toLowerCase();
  return (
    ct === "mobile_device" ||
    ct === "mobile_forensic" ||
    rt === "mobile_forensic" ||
    rt === "mobile_device"
  );
}

export function JobIntakePage() {
  const { jobId } = useParams<{ jobId: string }>();
  const location = useLocation();
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState<IntakePatch>({});

  // Subjects (person(s) under investigation)
  const [subjects, setSubjects] = useState<CaseSubjectInput[]>([{ name: "", email: "", role: "" }]);

  // Report configuration (relocated from the Report editor)
  const [reportTypes, setReportTypes] = useState<ReportTypeOption[]>([]);
  const [caseTypes, setCaseTypes] = useState<CaseTypeOption[]>([]);
  const [caseType, setCaseType] = useState("general_computer_forensic");
  const [reportType, setReportType] = useState("general_computer_forensic");
  const [objectives, setObjectives] = useState<ReportObjectiveOption[]>([]);
  const [recommendedIds, setRecommendedIds] = useState<string[]>([]);
  const [selectedObjectives, setSelectedObjectives] = useState<Set<string>>(new Set());
  const [objectiveSearch, setObjectiveSearch] = useState("");
  const [customObjectives, setCustomObjectives] = useState<CustomObjectiveInput[]>([]);
  const [customTitle, setCustomTitle] = useState("");
  const [customObjective, setCustomObjective] = useState("");
  const [customProcedure, setCustomProcedure] = useState("");
  const [showCustom, setShowCustom] = useState(false);
  const [forensicKeys, setForensicKeys] = useState({
    ios_backup_password: "",
    whatsapp_key_hex: "",
    signal_passphrase: "",
    signal_db_key_hex: "",
    keychain_password: "",
    adb_backup_password: "",
  });
  const [keyStatus, setKeyStatus] = useState<Record<string, boolean>>({});

  // Gate state from the server.
  const [missing, setMissing] = useState<string[]>([]);
  const [reportReady, setReportReady] = useState(false);
  const [validating, setValidating] = useState(false);
  const [agentSuggestions, setAgentSuggestions] = useState<string[]>([]);
  const intakeLoadedRef = useRef(false);

  const load = useCallback(async () => {
    if (!jobId) return;
    intakeLoadedRef.current = false;
    setLoading(true);
    try {
      const intake: Intake = await forensicApi.getIntake(jobId);
      setForm({
        case_type: intake.case_type,
        organization: intake.organization,
        address: intake.address,
        evidence_description: intake.evidence_description,
        seizure_date: intake.seizure_date,
        background: intake.background,
        incident_summary: intake.incident_summary,
        pre_seizure_consent: intake.pre_seizure_consent,
        evidence_handling: intake.evidence_handling,
      });
      if (intake.case_type) setCaseType(intake.case_type);
      if (intake.report_type) setReportType(intake.report_type);
      if (isMobileCaseType(intake.case_type, intake.report_type)) {
        setSelectedObjectives(new Set());
        setCustomObjectives([]);
      } else if (intake.objective_ids?.length) {
        setSelectedObjectives(new Set(intake.objective_ids));
        if (intake.custom_objectives) setCustomObjectives(intake.custom_objectives);
      } else {
        setSelectedObjectives(new Set());
        if (intake.custom_objectives) setCustomObjectives(intake.custom_objectives);
      }
      if (intake.subjects && intake.subjects.length > 0) {
        setSubjects(intake.subjects.map((s) => ({ name: s.name, email: s.email ?? "", role: s.role ?? "" })));
      }
      setForm((f) => ({
        ...f,
        requesting_agency: intake.requesting_agency,
        case_number: intake.case_number,
        examiner_name: intake.examiner_name,
        lab_location: intake.lab_location,
        evidence_received_date: intake.evidence_received_date,
        chain_of_custody_ref: intake.chain_of_custody_ref,
        vol18_form_json: intake.vol18_form_json ?? {},
      }));
      setMissing(intake.missing_fields ?? []);
      setReportReady(intake.report_ready ?? false);
      setKeyStatus(intake.forensic_key_status ?? {});
      intakeLoadedRef.current = true;
    } catch {
      setForm({});
      intakeLoadedRef.current = true;
    } finally {
      setLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    forensicApi
      .listCaseTypes()
      .then((res) => setCaseTypes(res.items))
      .catch(() =>
        setCaseTypes([{ id: "general_computer_forensic", label: "General Computer Forensic", default_report_type_id: "general_computer_forensic" }])
      );
  }, []);

  useEffect(() => {
    forensicApi
      .listReportTypes()
      .then((res) => setReportTypes(res.items))
      .catch(() => setReportTypes([{ id: "general_computer_forensic", label: "General Computer Forensic Report" }]));
  }, []);

  useEffect(() => {
    if (!intakeLoadedRef.current) return;
    if (isMobileCaseType(caseType, reportType)) {
      setObjectives([]);
      setRecommendedIds([]);
      setSelectedObjectives(new Set());
      return;
    }
    forensicApi
      .listReportObjectives(reportType)
      .then((res) => {
        setObjectives(dedupeObjectiveOptions(res.items));
        const rec = res.recommended_ids ?? res.items.filter((o) => o.in_template ?? o.recommended).map((o) => o.id);
        setRecommendedIds(rec);
        setSelectedObjectives((prev) => (prev.size === 0 ? new Set(rec) : prev));
      })
      .catch(() => setObjectives([]));
  }, [reportType, caseType]);

  function onCaseTypeChange(nextType: string) {
    setCaseType(nextType);
    setForm((f) => ({ ...f, case_type: nextType }));
    if (isMobileCaseType(nextType)) {
      setSelectedObjectives(new Set());
      setCustomObjectives([]);
    }
    const selected = caseTypes.find((t) => t.id === nextType);
    const nextReport = selected?.default_report_type_id;
    if (nextReport) {
      onReportTypeChange(nextReport);
    }
  }

  function onReportTypeChange(nextType: string) {
    setReportType(nextType);
    if (isMobileCaseType(caseType, nextType)) {
      setObjectives([]);
      setRecommendedIds([]);
      setSelectedObjectives(new Set());
      setCustomObjectives([]);
      return;
    }
    forensicApi
      .listReportObjectives(nextType)
      .then((res) => {
        setObjectives(dedupeObjectiveOptions(res.items));
        const rec = res.recommended_ids ?? res.items.filter((o) => o.in_template ?? o.recommended).map((o) => o.id);
        setRecommendedIds(rec);
        setSelectedObjectives(new Set(rec));
      })
      .catch(() => setObjectives([]));
  }

  const mobileIntake = isMobileCaseType(caseType, reportType);
  const mobileRoute = location.pathname.startsWith("/mobile/");
  const mobileBase = location.pathname.startsWith("/mobile/android/")
    ? "/mobile/android"
    : location.pathname.startsWith("/mobile/ios/")
      ? "/mobile/ios"
      : "/mobile";
  const artifactsHref = mobileRoute ? `${mobileBase}/jobs/${jobId}/artifacts` : `/forensic/jobs/${jobId}/artifacts`;
  const reportHref = mobileRoute ? `${mobileBase}/jobs/${jobId}/report` : `/forensic/jobs/${jobId}/report`;

  const selectedCaseType = useMemo(
    () => caseTypes.find((t) => t.id === caseType),
    [caseTypes, caseType],
  );

  const selectedReportType = useMemo(
    () => reportTypes.find((t) => t.id === reportType),
    [reportTypes, reportType],
  );

  const filteredObjectives = useMemo(() => {
    const q = objectiveSearch.trim().toLowerCase();
    const matched = !q
      ? objectives
      : objectives.filter(
          (o) => o.title.toLowerCase().includes(q) || o.objective.toLowerCase().includes(q),
        );
    return dedupeObjectiveOptions(matched);
  }, [objectives, objectiveSearch]);

  function toggleObjective(id: string) {
    setSelectedObjectives((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function addCustomObjective() {
    const title = customTitle.trim();
    const objective = customObjective.trim();
    if (!title || !objective) {
      toast.error("Custom objective needs a title and objective statement");
      return;
    }
    setCustomObjectives((prev) => [...prev, { title, objective, procedure: customProcedure.trim() || null }]);
    setCustomTitle("");
    setCustomObjective("");
    setCustomProcedure("");
    setShowCustom(false);
  }

  function setField(key: keyof IntakePatch, value: string) {
    setForm((f) => ({ ...f, [key]: value || null }));
  }

  function setSubject(idx: number, key: keyof CaseSubjectInput, value: string) {
    setSubjects((prev) => prev.map((s, i) => (i === idx ? { ...s, [key]: value } : s)));
  }

  function addSubject() {
    setSubjects((prev) => [...prev, { name: "", email: "", role: "" }]);
  }

  function removeSubject(idx: number) {
    setSubjects((prev) => (prev.length <= 1 ? prev : prev.filter((_, i) => i !== idx)));
  }

  async function validateWithAgent() {
    if (!jobId) return;
    setValidating(true);
    try {
      const res = await forensicApi.intakeValidate(jobId);
      setAgentSuggestions((res.output?.suggestions as string[]) ?? []);
      if (res.status === "success") toast.success(res.message || "Intake validated");
      else toast.error(res.message || "Intake incomplete");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Agent validation failed");
    } finally {
      setValidating(false);
    }
  }

  async function save() {
    if (!jobId) return;
    setSaving(true);
    try {
      const cleanedSubjects = subjects
        .map((s) => ({ name: s.name.trim(), email: (s.email ?? "").trim(), role: (s.role ?? "").trim() }))
        .filter((s) => s.name.length > 0);
      const mobile = isMobileCaseType(caseType, reportType);
      const payload: IntakePatch = {
        ...form,
        case_type: caseType,
        report_type: reportType,
        // Mobile forensic reports do not use examination objectives.
        objective_ids: mobile ? [] : Array.from(selectedObjectives),
        custom_objectives: mobile ? [] : customObjectives,
        subjects: cleanedSubjects,
        forensic_keys: {
          ios_backup_password: forensicKeys.ios_backup_password || null,
          whatsapp_key_hex: forensicKeys.whatsapp_key_hex || null,
          signal_passphrase: forensicKeys.signal_passphrase || null,
          signal_db_key_hex: forensicKeys.signal_db_key_hex || null,
          keychain_password: forensicKeys.keychain_password || null,
          adb_backup_password: forensicKeys.adb_backup_password || null,
        },
      };
      const intake: Intake = await forensicApi.patchIntake(jobId, payload);
      setMissing(intake.missing_fields ?? []);
      setReportReady(intake.report_ready ?? false);
      setKeyStatus(intake.forensic_key_status ?? {});
      setForensicKeys({
        ios_backup_password: "",
        whatsapp_key_hex: "",
        signal_passphrase: "",
        signal_db_key_hex: "",
        keychain_password: "",
        adb_backup_password: "",
      });
      toast.success("Intake saved");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <Spinner />;

  return (
    <div>
      <PageHeader
        title="Case intake"
        subtitle="Capture case metadata, subject(s) under investigation, and the report configuration. The report can only be generated once this is complete."
        actions={
          <div className="flex flex-wrap gap-2">
            <Link to={artifactsHref}>
              <Button variant="ghost">
                <ArrowLeft className="h-4 w-4" /> Back to Artifacts
              </Button>
            </Link>
            <Button variant="brand" loading={saving} onClick={save}>
              <Save className="h-4 w-4" /> Save intake
            </Button>
            {reportReady ? (
              <Link to={reportHref}>
                <Button variant="outline">Continue to Report <ArrowRight className="h-4 w-4" /></Button>
              </Link>
            ) : null}
          </div>
        }
      />

      {/* Gate banner */}
      {reportReady ? (
        <Card className="mb-4 border-green-200 bg-green-50/50 p-3 text-sm text-green-800">
          Intake complete — continue to Report using the button above.
        </Card>
      ) : (
        <Card className="mb-4 border-amber-200 bg-amber-50/50 p-3 text-sm text-amber-800">
          Report generation is blocked until intake is complete. Missing:{" "}
          {missing.length > 0 ? missing.map((m) => MISSING_LABEL[m] ?? m).join(", ") : "save the form to validate"}.
        </Card>
      )}

      {/* Subjects */}
      <Card className="mb-4 max-w-3xl p-6">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <p className="font-medium text-ink-800">Subject(s) under investigation</p>
            <p className="text-sm text-ink-500">The person(s) the case is about. Name and email are required for at least one.</p>
          </div>
          <Button variant="outline" onClick={addSubject}>
            <UserPlus className="h-4 w-4" /> Add person
          </Button>
        </div>
        <div className="space-y-3">
          {subjects.map((s, idx) => (
            <div key={idx} className="grid items-end gap-2 sm:grid-cols-[1fr_1fr_0.7fr_auto]">
              <Field label={idx === 0 ? "Name" : ""}>
                <Input value={s.name} placeholder="Full name" onChange={(e) => setSubject(idx, "name", e.target.value)} />
              </Field>
              <Field label={idx === 0 ? "Email" : ""}>
                <Input value={s.email ?? ""} placeholder="name@example.com" onChange={(e) => setSubject(idx, "email", e.target.value)} />
              </Field>
              <Field label={idx === 0 ? "Role (optional)" : ""}>
                <Input value={s.role ?? ""} placeholder="Custodian" onChange={(e) => setSubject(idx, "role", e.target.value)} />
              </Field>
              <Button
                variant="ghost"
                onClick={() => removeSubject(idx)}
                disabled={subjects.length <= 1}
                aria-label="Remove person"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          ))}
        </div>
      </Card>

      {/* Case metadata */}
      <Card className="mb-4 max-w-3xl p-6">
        <p className="mb-3 font-medium text-ink-800">Case metadata</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Case type">
            <Select value={caseType} onChange={(e) => onCaseTypeChange(e.target.value)}>
              {caseTypes.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </Select>
            {selectedCaseType?.description ? (
              <p className="mt-1 text-xs text-ink-500">{selectedCaseType.description}</p>
            ) : null}
          </Field>
          <Field label="Organization">
            <Input value={form.organization ?? ""} onChange={(e) => setField("organization", e.target.value)} />
          </Field>
          <Field label="Seizure date">
            <Input
              type="datetime-local"
              value={form.seizure_date?.slice(0, 16) ?? ""}
              onChange={(e) =>
                setForm((f) => ({ ...f, seizure_date: e.target.value ? new Date(e.target.value).toISOString() : null }))
              }
            />
          </Field>
          <Field label="Address">
            <Input value={form.address ?? ""} onChange={(e) => setField("address", e.target.value)} />
          </Field>
          <div className="sm:col-span-2">
            <Field label="Evidence description">
              <textarea className="input min-h-[80px] resize-y" value={form.evidence_description ?? ""} onChange={(e) => setField("evidence_description", e.target.value)} />
            </Field>
          </div>
          <div className="sm:col-span-2">
            <Field label="Background">
              <textarea className="input min-h-[80px] resize-y" value={form.background ?? ""} onChange={(e) => setField("background", e.target.value)} />
            </Field>
          </div>
          <div className="sm:col-span-2">
            <Field label="Incident summary">
              <textarea className="input min-h-[80px] resize-y" value={form.incident_summary ?? ""} onChange={(e) => setField("incident_summary", e.target.value)} />
            </Field>
          </div>
          <div className="sm:col-span-2">
            <Field label="Pre-seizure consent">
              <textarea className="input min-h-[60px] resize-y" value={form.pre_seizure_consent ?? ""} onChange={(e) => setField("pre_seizure_consent", e.target.value)} />
            </Field>
          </div>
          <div className="sm:col-span-2">
            <Field label="Evidence handling">
              <textarea className="input min-h-[60px] resize-y" value={form.evidence_handling ?? ""} onChange={(e) => setField("evidence_handling", e.target.value)} />
            </Field>
          </div>
        </div>
      </Card>

      {/* Vol18 / chain-of-custody (export defensibility) */}
      <Card className="mb-4 max-w-3xl p-6">
        <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-500">Vol18 intake &amp; chain of custody</p>
        <p className="mb-4 text-sm text-ink-500">
          Used in exported report headers and defensibility manifest (CoC hooks for Vol16 compliance pack).
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Case number">
            <Input value={form.case_number ?? ""} onChange={(e) => setField("case_number", e.target.value)} />
          </Field>
          <Field label="Requesting agency">
            <Input value={form.requesting_agency ?? ""} onChange={(e) => setField("requesting_agency", e.target.value)} />
          </Field>
          <Field label="Examiner name">
            <Input value={form.examiner_name ?? ""} onChange={(e) => setField("examiner_name", e.target.value)} />
          </Field>
          <Field label="Lab location">
            <Input value={form.lab_location ?? ""} onChange={(e) => setField("lab_location", e.target.value)} />
          </Field>
          <Field label="Evidence received date">
            <Input
              type="date"
              value={form.evidence_received_date?.slice(0, 10) ?? ""}
              onChange={(e) => setField("evidence_received_date", e.target.value)}
            />
          </Field>
          <Field label="Chain of custody reference">
            <Input value={form.chain_of_custody_ref ?? ""} onChange={(e) => setField("chain_of_custody_ref", e.target.value)} />
          </Field>
        </div>
      </Card>

      <Card className="mb-4 max-w-3xl p-6">
        <p className="mb-3 font-medium text-ink-800">Decrypt keys (per job, encrypted at rest)</p>
        <p className="mb-4 text-xs text-ink-500">
          Leave blank to keep existing values. Keys apply to iOS backups, WhatsApp/Signal databases, ADB backups, and macOS keychain during extraction.
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          {(
            [
              ["ios_backup_password", "iOS backup password", keyStatus.ios_backup_password_set],
              ["whatsapp_key_hex", "WhatsApp key (64-char AES hex, or hex of files/key)", keyStatus.whatsapp_key_hex_set],
              ["signal_passphrase", "Signal passphrase", keyStatus.signal_passphrase_set],
              ["signal_db_key_hex", "Signal DB key (hex)", keyStatus.signal_db_key_hex_set],
              ["keychain_password", "macOS keychain password", keyStatus.keychain_password_set],
              ["adb_backup_password", "ADB backup password", keyStatus.adb_backup_password_set],
            ] as const
          ).map(([field, label, isSet]) => (
            <Field key={field} label={label} hint={isSet ? "Currently set — enter new value to replace" : undefined}>
              <Input
                type="password"
                autoComplete="off"
                value={forensicKeys[field]}
                onChange={(e) => setForensicKeys((k) => ({ ...k, [field]: e.target.value }))}
              />
            </Field>
          ))}
        </div>
      </Card>

      {/* Report configuration — objectives required for disk only; mobile uses default findings. */}
      <Card className="max-w-3xl p-6">
        <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-500">Report configuration</p>
        <p className="mb-4 text-sm text-ink-500">
          {mobileIntake
            ? "Mobile Device Examination does not require examination objectives. Findings are generated from the extraction evidence and case background."
            : "Select report type and examination objectives. All objectives are shown; objectives included in the selected report type are checked automatically. You may add or remove selections and add custom objectives."}
        </p>
        <div className="mb-4 grid gap-4 sm:grid-cols-2">
          <Field label="Report type">
            <Select value={reportType} onChange={(e) => onReportTypeChange(e.target.value)}>
              {reportTypes.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                  {t.domain ? ` (${t.domain})` : ""}
                </option>
              ))}
            </Select>
          </Field>
          <div className="flex flex-col justify-end text-sm text-ink-500">
            {selectedReportType?.default_os?.length ? (
              <span>OS focus: {selectedReportType.default_os.join(", ")}</span>
            ) : null}
            {selectedReportType?.description ? (
              <span className="text-xs">{selectedReportType.description}</span>
            ) : null}
            {!mobileIntake ? (
              <span className="mt-1">
                Objectives ({selectedObjectives.size} selected of {objectives.length} available + {customObjectives.length} custom)
              </span>
            ) : (
              <span className="mt-1">Objectives not required for mobile reports</span>
            )}
          </div>
        </div>

        {!mobileIntake ? (
        <div className="mb-3 flex flex-wrap gap-2">
          <Button variant="outline" loading={validating} onClick={() => void validateWithAgent()}>
            Validate with agent
          </Button>
          <Button variant="outline" onClick={() => setSelectedObjectives(new Set(recommendedIds))}>Use recommended</Button>
          <Button variant="outline" onClick={() => setSelectedObjectives(new Set(objectives.map((o) => o.id)))}>Select all</Button>
          <Button variant="outline" onClick={() => setSelectedObjectives(new Set())}>Clear selection</Button>
          <Button variant="outline" onClick={() => setShowCustom((v) => !v)}>
            <Plus className="h-4 w-4" /> Add custom objective
          </Button>
        </div>
        ) : (
        <div className="mb-3 flex flex-wrap gap-2">
          <Button variant="outline" loading={validating} onClick={() => void validateWithAgent()}>
            Validate with agent
          </Button>
        </div>
        )}

        {agentSuggestions.length > 0 && (
          <Card className="mb-3 border-indigo-100 bg-indigo-50/50 p-3 text-sm text-indigo-900">
            <p className="font-medium">Agent suggestions</p>
            <ul className="mt-1 list-inside list-disc text-indigo-800">
              {agentSuggestions.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ul>
          </Card>
        )}

        {!mobileIntake ? (
          <>
            <Input className="mb-3" placeholder="Search objectives…" value={objectiveSearch} onChange={(e) => setObjectiveSearch(e.target.value)} />

            {showCustom && (
              <Card className="mb-3 p-3">
                <p className="text-sm font-medium text-ink-800">Custom objective</p>
                <Input className="mt-2" placeholder="Title" value={customTitle} onChange={(e) => setCustomTitle(e.target.value)} />
                <textarea className="input mt-2 min-h-[60px] resize-y" placeholder="Objective statement" value={customObjective} onChange={(e) => setCustomObjective(e.target.value)} />
                <textarea className="input mt-2 min-h-[60px] resize-y" placeholder="Procedure (optional)" value={customProcedure} onChange={(e) => setCustomProcedure(e.target.value)} />
                <div className="mt-2 flex justify-end">
                  <Button variant="brand" onClick={addCustomObjective}>Add objective</Button>
                </div>
              </Card>
            )}

            <div className="min-h-[480px] max-h-[calc(100vh-240px)] space-y-2 overflow-y-auto pr-1">
              {filteredObjectives.map((o) => {
                const checked = selectedObjectives.has(o.id);
                return (
                  <label
                    key={o.id}
                    className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 ${checked ? "border-brand-300 bg-brand-50/40" : "border-ink-100"}`}
                  >
                    <input type="checkbox" className="mt-1" checked={checked} onChange={() => toggleObjective(o.id)} />
                    <span>
                      <span className="font-medium text-ink-800">
                        {o.title}{" "}
                        {recommendedIds.includes(o.id) && (
                          <span className="text-xs font-normal text-green-600">included in report type</span>
                        )}
                      </span>
                      <span className="block text-sm text-ink-500">{o.objective}</span>
                      {(o.procedure || o.procedure_text) && (
                        <span className="mt-1 block text-xs text-ink-500">
                          Procedure: {o.procedure || o.procedure_text}
                        </span>
                      )}
                      {o.evidence_questions && o.evidence_questions.length > 0 && (
                        <span className="mt-1 block text-xs text-ink-400">
                          Evidence questions: {o.evidence_questions.join(" · ")}
                        </span>
                      )}
                    </span>
                  </label>
                );
              })}
            </div>

            {customObjectives.length > 0 && (
              <div className="mt-3 space-y-1 border-t border-ink-100 pt-3">
                <p className="text-sm font-medium text-ink-700">Custom objectives</p>
                {customObjectives.map((c, i) => (
                  <div key={i} className="flex items-center justify-between rounded border border-ink-100 px-2 py-1 text-sm">
                    <span>{c.title}</span>
                    <Button variant="ghost" onClick={() => setCustomObjectives((p) => p.filter((_, j) => j !== i))} aria-label="Remove custom objective">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </>
        ) : null}
      </Card>
    </div>
  );
}
