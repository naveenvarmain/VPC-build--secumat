(() => {
    "use strict";

    let resources = [
        "Audit Questions for companies.xlsx",
        "CDR_3rd Party SaaS_CRQ123456_ProjectName__v1.3.0.xlsx",
        "CDR_Enterprise IT_CRQ123456_ProjectName__v1.2.0.xlsx",
        "CDR_Product_CRQ123456_ProjectName__v1.0.0.xlsx",
        "IC-ISO-27001-Auditor-Checklist-10838.xlsx",
        "IC-ISO-27001-Business-Continuity-Checklist-10838.xlsx",
        "IC-ISO-27001-Checklist-10838.xlsx",
        "IC-ISO-27001-Compliance-Checklist-10838.xlsx",
        "IC-ISO-27001-Internal-Audit-Schedule-10838.xlsx",
        "IC-ISO-27001-Risk-Assessment-10838.xlsx",
        "IC-ISO-27001-Sample-Form-10838.xlsx",
        "IC-ISO-27002-Information-Security-Guidelines-Checklist-10838.xlsx",
        "IC-IT-Risk-Acceptance-Form-11644.xlsx",
        "IC-IT-Risk-Assessment-Checklist-Example-11644.xlsx",
        "IC-IT-Risk-Assessment-Policy-11644_WORD.docx",
        "IC-IT-Risk-Register-11644.xlsx",
        "ISO 42001 questions for auditing.xlsx",
        "IT RISK ANALYSIS TEMPLATE.xlsx",
        "IT RISK ASSESSMENT DASHBOARD REPORT TEMPLATE.xlsx",
        "IT RISK ASSESSMENT MATRIX TEMPLATE.xlsx",
        "IT RISK MANAGEMENT planning template.xlsx",
        "IT-Risk-Management-Plan-11644_WORD.docx",
        "Security-Questionnaire.xlsx",
        "SIMPLE IT RISK ASSESSMENT TEMPLATE .xlsx",
        "Third Party-Security-Questionnaire-v2.0.xlsx",
        "ZF Security Maturity Secumat_CIS_Controls_Version_8_NIST_ISO27k1_updated Questionnaire.xlsx"
    ];
    const pageSize = 40;
    const ratingScores = {
        compliant: 100,
        compensating_control: 75,
        partial: 50,
        non_compliant: 0,
        needs_review: 0,
        deferred: 0,
        not_applicable: null
    };
    const ratingOptions = [
        ["", "Not rated"],
        ["compliant", "Compliant (100%)"],
        ["compensating_control", "Compensating control (75%)"],
        ["partial", "Partially compliant (50%)"],
        ["non_compliant", "Non-compliant (0%)"],
        ["needs_review", "Needs review (0%)"],
        ["deferred", "Deferred (0%)"],
        ["not_applicable", "Not applicable"]
    ];
    const elements = {
        catalog: document.getElementById("secumatResourceCatalog"),
        workspace: document.getElementById("secumatQuestionnaireWorkbench"),
        title: document.getElementById("secumatQuestionnaireTitle"),
        fileMeta: document.getElementById("secumatQuestionnaireMeta"),
        sheetSelect: document.getElementById("secumatQuestionnaireSheet"),
        tabs: document.getElementById("secumatWorkbookTabs"),
        search: document.getElementById("secumatQuestionnaireSearch"),
        editButton: document.getElementById("secumatQuestionnaireEdit"),
        saveButton: document.getElementById("secumatQuestionnaireSave"),
        saveAsButton: document.getElementById("secumatQuestionnaireSaveAs"),
        submitButton: document.getElementById("secumatQuestionnaireSubmit"),
        history: document.getElementById("secumatQuestionnaireHistory"),
        versions: document.getElementById("secumatQuestionnaireVersions"),
        assignmentSelect: document.getElementById("secumatWorkbookAssignment"),
        assignmentStatus: document.getElementById("secumatWorkbookAssignmentStatus"),
        historyBody: document.getElementById("secumatWorkbookHistoryBody"),
        nameInput: document.getElementById("secumatWorkbookName"),
        submitDialog: document.getElementById("secumatWorkbookSubmitDialog"),
        discardButton: document.getElementById("secumatWorkbookDiscard"),
        exportButton: document.getElementById("secumatQuestionnaireExport"),
        downloadLink: document.getElementById("secumatQuestionnaireDownload"),
        summary: document.getElementById("secumatQuestionnaireSummary"),
        status: document.getElementById("secumatQuestionnaireStatus"),
        table: document.getElementById("secumatQuestionnaireTable"),
        pagination: document.getElementById("secumatQuestionnairePagination")
    };
    const state = {
        workbook: null,
        workbookBytes: null,
        fileName: "",
        sheetName: "",
        questions: [],
        sheets: {},
        auditId: "",
        assignmentId: "",
        assignments: [],
        auditName: "",
        version: 0,
        submitted: false,
        historical: false,
        busy: false,
        editing: false,
        dirty: false,
        page: 0,
        search: ""
    };

    function escapeHtml(value) {
        return String(value ?? "").replace(/[&<>"']/g, character => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
        })[character]);
    }

    function resourceUrl(fileName) {
        return `/Audit%20Templates%20%26%20Question%20Bank/${encodeURIComponent(fileName)}`;
    }

    function isSpreadsheet(fileName) {
        return /\.(xlsx|xls|csv)$/i.test(fileName);
    }

    function renderCatalog() {
        if (!elements.catalog) return;
        elements.catalog.innerHTML = `<div class="secumat-questionnaire-controls"><label>Audit template<select id="secumatTemplateChoice"><option value="">Select a template</option>${resources.map(fileName => `<option value="${escapeHtml(fileName)}">${escapeHtml(fileName)}</option>`).join("")}</select></label><label>Assign to<input id="secumatTemplateAssignee" type="text" maxlength="200" placeholder="Name, email, or team"></label><label>Assignee type<select id="secumatTemplateAssigneeType"><option value="person">Person</option><option value="team">Team</option></select></label><button type="button" id="secumatTemplateAssign" disabled>Assign</button><button type="button" id="secumatTemplateLoad" disabled>Load Questionnaire</button><a id="secumatTemplateExcel" href="#" target="_blank" rel="noopener noreferrer" aria-disabled="true">Open Excel file</a><a id="secumatTemplateWindow" href="#" target="_blank" rel="noopener noreferrer" aria-disabled="true">Open editor window</a></div><p id="secumatTemplateStatus" role="status" aria-live="polite"></p>`;
    }

    async function loadCatalog() {
        try {
            const response = await fetch("/api/secumat_templates");
            if (!response.ok) throw new Error(`Template request failed (${response.status})`);
            const data = await response.json();
            resources = data.templates.map(item => item.name);
        } catch (error) {
            setStatus(`Using bundled template list: ${error.message}`, "warning");
        }
        renderCatalog();
    }

    function headerScore(values) {
        const words = /\bquestions?\b|\brequirements?\b|\bcontrol\b|\bclause\b|\breference\b|\bidentifier\b|\bdomain\b|\bsection\b|\bcategory\b|\bresponse\b|\banswer\b|\brating\b|\bevidence\b|\bdescription\b|\bstatement\b|\brisk\b|\bobjective\b/i;
        return values.reduce((score, value) => score + (words.test(String(value ?? "")) ? 1 : 0), 0);
    }

    function headerIndexFor(rows) {
        let bestIndex = 0;
        let bestScore = 0;
        rows.slice(0, 20).forEach((values, index) => {
            const score = headerScore(values);
            if (score > bestScore) {
                bestScore = score;
                bestIndex = index;
            }
        });
        return { index: bestIndex, score: bestScore };
    }

    function columnIndex(headers, pattern) {
        return headers.findIndex(header => pattern.test(String(header ?? "")));
    }

    function readSheet(sheetName) {
        const worksheet = state.workbook.Sheets[sheetName];
        const range = window.XLSX.utils.decode_range(worksheet["!ref"] || "A1");
        const values = window.XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "", raw: false, blankrows: true, range: { s: { r: 0, c: 0 }, e: range.e } });
        const headerInfo = headerIndexFor(values);
        const headers = Array.from({ length: range.e.c + 1 }, (_, index) => String(values[headerInfo.index]?.[index] || `Column ${index + 1}`).trim());
        const referenceColumn = columnIndex(headers, /reference|control\s*(id|no|number|ref)|clause|identifier|^id$|^no\.?$/i);
        const questionColumn = columnIndex(headers, /\bquestions?\b|\brequirements?\b|control\s*objective|\bobjective\b|\bstatement\b|\bdescription\b|audit step|^q\.?$/i);
        const sectionColumn = columnIndex(headers, /domain|section|category|topic|area|principle/i);
        const rows = values.map((cells, offset) => {
            const normalizedCells = headers.map((_, index) => String(cells[index] ?? ""));
            const question = questionColumn >= 0
                ? normalizedCells[questionColumn]
                : normalizedCells.filter(Boolean).join(" | ");
            return {
                id: `row-${offset + 1}`,
                reference: referenceColumn >= 0 ? normalizedCells[referenceColumn] : String(offset + 1),
                section: sectionColumn >= 0 ? normalizedCells[sectionColumn] : "",
                question,
                rating: "",
                evidence: "",
                sourceCells: normalizedCells
            };
        });
        return { sheetName, headers, rows, original: rows.map(item => [...item.sourceCells]), baseRowCount: rows.length, questionColumn, referenceColumn, sectionColumn, headerScore: headerInfo.score, hasQuestionColumn: questionColumn >= 0 };
    }

    function recoverBrowserReviews() {
        let recovered = false;
        Object.entries(state.sheets).forEach(([sheetName, sheet]) => {
            let saved;
            try { saved = JSON.parse(localStorage.getItem(`secumat.audit-questionnaire.v1:${state.fileName}:${sheetName}`) || "null"); } catch { return; }
            if (!Array.isArray(saved?.items)) return;
            const byId = new Map(saved.items.map(item => [item.id, item]));
            sheet.rows.forEach(row => {
                const old = byId.get(row.id);
                if (!old) return;
                row.rating = old.rating || "";
                row.evidence = old.evidence || "";
                if (sheet.questionColumn >= 0 && old.question !== undefined) row.sourceCells[sheet.questionColumn] = String(old.question);
            });
            (saved.deletedIds || []).forEach(id => {
                const row = sheet.rows.find(item => item.id === id);
                if (row) row.sourceCells.fill("");
            });
            saved.items.filter(item => String(item.id).startsWith("new-")).forEach(item => {
                const rowNumber = sheet.rows.length + 1;
                const cells = sheet.headers.map(() => "");
                cells[sheet.questionColumn >= 0 ? sheet.questionColumn : 0] = String(item.question || "");
                if (sheet.referenceColumn >= 0) cells[sheet.referenceColumn] = String(item.reference || "");
                if (sheet.sectionColumn >= 0) cells[sheet.sectionColumn] = String(item.section || "");
                sheet.original.push(sheet.headers.map(() => ""));
                sheet.rows.push({ id: `row-${rowNumber}`, reference: item.reference || "", section: item.section || "", question: item.question || "", rating: item.rating || "", evidence: item.evidence || "", sourceCells: cells });
            });
            recovered = true;
        });
        return recovered;
    }

    function setStatus(message, kind = "info") {
        if (!elements.status) return;
        elements.status.textContent = message;
        elements.status.dataset.kind = kind;
    }

    function renderSheetOptions(sheetNames, preferredSheet) {
        elements.sheetSelect.innerHTML = sheetNames.map(sheetName => `<option value="${escapeHtml(sheetName)}" ${sheetName === preferredSheet ? "selected" : ""}>${escapeHtml(sheetName)}</option>`).join("");
        elements.sheetSelect.disabled = false;
        elements.tabs.innerHTML = sheetNames.map(sheetName => `<button type="button" role="tab" data-workbook-sheet="${escapeHtml(sheetName)}" aria-selected="${sheetName === preferredSheet}">${escapeHtml(sheetName)}</button>`).join("");
    }

    function loadSheet(sheetName) {
        const sheet = state.sheets[sheetName];
        state.sheetName = sheetName;
        elements.sheetSelect.value = sheetName;
        elements.tabs.querySelectorAll("[data-workbook-sheet]").forEach(tab => { tab.setAttribute("aria-selected", String(tab.dataset.workbookSheet === sheetName)); });
        state.questions = sheet.rows;
        state.page = 0;
        state.search = "";
        elements.search.value = "";
        elements.search.disabled = false;
        elements.editButton.disabled = false;
        elements.exportButton.disabled = false;
        elements.fileMeta.textContent = `${state.workbook.SheetNames.length} sheets · ${sheet.rows.length.toLocaleString()} rows · ${sheet.headers.length} columns · ${state.auditName || "Unsaved draft"}`;
        renderQuestions();
    }

    async function loadQuestionnaire(fileName) {
        if (state.dirty) { setStatus("Save or discard workbook edits before loading another template.", "warning"); return; }
        if (!window.XLSX) {
            setStatus("The spreadsheet reader is unavailable. Check the connection and reload SECUMAT.", "error");
            return;
        }
        setStatus(`Loading ${fileName}...`);
        try {
            const response = await fetch(resourceUrl(fileName), { cache: "no-store" });
            if (!response.ok) throw new Error(`File request failed (${response.status}).`);
            const workbookBytes = new Uint8Array(await response.arrayBuffer());
            const workbook = window.XLSX.read(workbookBytes, { type: "array" });
            if (!workbook.SheetNames.length) throw new Error("The workbook contains no worksheets.");
            state.workbookBytes = workbookBytes;
            state.workbook = workbook;
            state.fileName = fileName;
            state.sheets = {};
            state.auditId = "";
            state.assignmentId = "";
            state.auditName = "";
            elements.nameInput.value = fileName.replace(/\.[^.]+$/, "");
            state.version = 0;
            state.submitted = false;
            state.historical = false;
            state.editing = false;
            state.dirty = false;
            elements.title.textContent = fileName;
            elements.downloadLink.href = resourceUrl(fileName);
            elements.downloadLink.download = fileName;
            elements.workspace.hidden = false;
            const sheetDetails = workbook.SheetNames.map(readSheet);
            sheetDetails.forEach(sheet => { state.sheets[sheet.sheetName] = sheet; });
            const recovered = recoverBrowserReviews();
            state.dirty = recovered;
            const contentSheets = sheetDetails.filter(sheet => !/^(overview|how to use|summary|lookups?|instructions?|read me|cover)$/i.test(sheet.sheetName.trim()));
            const bestSheet = (contentSheets.length ? contentSheets : sheetDetails).reduce((best, current) => {
                const currentScore = Number(current.hasQuestionColumn) * 1000000 + current.headerScore * 1000 + Math.min(current.rows.length, 999);
                const bestScore = Number(best.hasQuestionColumn) * 1000000 + best.headerScore * 1000 + Math.min(best.rows.length, 999);
                return currentScore > bestScore ? current : best;
            });
            renderSheetOptions(workbook.SheetNames, bestSheet.sheetName);
            loadSheet(bestSheet.sheetName);
            await refreshHistory();
            await loadAssignments();
            setStatus(recovered ? "Recovered earlier browser-only reviews. Save Draft to add them to audit history." : `Loaded all ${workbook.SheetNames.length} worksheets. Edit cells, then save a draft or submit.`, recovered ? "warning" : "success");
            elements.workspace.scrollIntoView({ behavior: "smooth", block: "start" });
        } catch (error) {
            setStatus(`Could not load questionnaire: ${error.message}`, "error");
        }
    }

    function filteredQuestions() {
        const query = state.search.trim().toLowerCase();
        if (!query) return state.questions;
        return state.questions.filter(item => [item.evidence, ...item.sourceCells].join(" ").toLowerCase().includes(query));
    }

    function ratingOptionsHtml(currentValue) {
        return ratingOptions.map(([value, label]) => `<option value="${value}" ${value === currentValue ? "selected" : ""}>${label}</option>`).join("");
    }

    function questionRowHtml(item, pageIndex) {
        const ratingScore = item.rating ? ratingScores[item.rating] : undefined;
        const ratingText = !item.rating ? "Not rated" : ratingScore === null ? "N/A" : `${ratingScore}%`;
        const rowNumber = Number(item.id.slice(4));
        const cells = item.sourceCells.map((value, index) => `<td><textarea data-row="${rowNumber}" data-column="${index}" aria-label="${escapeHtml(window.XLSX.utils.encode_col(index))}${rowNumber}" rows="2" ${state.editing ? "" : "disabled"}>${escapeHtml(value)}</textarea></td>`).join("");
        return `<tr><th scope="row">${rowNumber}</th>${cells}<td><select data-row="${rowNumber}" data-field="rating" aria-label="Rating row ${rowNumber}" ${state.editing ? "" : "disabled"}>${ratingOptionsHtml(item.rating)}</select><small class="secumat-rating-value">${escapeHtml(ratingText)}</small></td><td><textarea data-row="${rowNumber}" data-field="evidence" rows="2" aria-label="Evidence row ${rowNumber}" ${state.editing ? "" : "disabled"}>${escapeHtml(item.evidence)}</textarea></td></tr>`;
    }

    function renderSummary() {
        const rated = state.questions.filter(item => item.rating);
        const scored = rated.filter(item => ratingScores[item.rating] !== null && ratingScores[item.rating] !== undefined);
        const score = scored.length ? Math.round(scored.reduce((total, item) => total + ratingScores[item.rating], 0) / scored.length) : null;
        const counts = ratingOptions.filter(([value]) => value).map(([value, label]) => {
            const count = state.questions.filter(item => item.rating === value).length;
            return count ? `<span>${escapeHtml(label.split(" (")[0])}: <strong>${count}</strong></span>` : "";
        }).filter(Boolean).join("");
        elements.summary.innerHTML = `<div class="secumat-rating-summary"><strong>Overall rating: ${score === null ? "Not rated" : `${score}%`}</strong><span>${rated.length}/${state.questions.length} rated</span>${counts}</div>`;
    }

    function renderQuestions() {
        if (!elements.table || !state.workbook) return;
        const matching = filteredQuestions();
        const pageCount = Math.max(1, Math.ceil(matching.length / pageSize));
        state.page = Math.min(state.page, pageCount - 1);
        const start = state.page * pageSize;
        const shown = matching.slice(start, start + pageSize);
        const columns = state.sheets[state.sheetName].headers.map((header, index) => `<th scope="col" title="${escapeHtml(header)}">${window.XLSX.utils.encode_col(index)}<small>${escapeHtml(header)}</small></th>`).join("");
        elements.table.innerHTML = `<div class="secumat-question-table-wrap"><table class="secumat-question-table"><thead><tr><th scope="col">#</th>${columns}<th scope="col">Rating</th><th scope="col">Evidence / notes</th></tr></thead><tbody>${shown.map(questionRowHtml).join("") || `<tr><td colspan="${state.sheets[state.sheetName].headers.length + 3}">No rows match this search.</td></tr>`}</tbody></table></div>`;
        elements.pagination.innerHTML = `<button type="button" data-question-page="previous" ${state.page === 0 ? "disabled" : ""}>Previous</button><span>Page ${state.page + 1} of ${pageCount} · ${matching.length.toLocaleString()} rows</span><button type="button" data-question-page="next" ${state.page + 1 >= pageCount ? "disabled" : ""}>Next</button>`;
        elements.saveButton.disabled = state.busy || state.submitted || state.historical || !state.dirty;
        elements.saveAsButton.disabled = state.busy;
        elements.submitButton.disabled = state.busy || state.submitted || state.historical;
        elements.editButton.disabled = state.busy || state.submitted || state.historical;
        elements.discardButton.disabled = state.busy || !state.dirty;
        renderSummary();
    }

    function markDirty() {
        state.dirty = true;
        elements.saveButton.disabled = false;
        setStatus("Unsaved workbook changes.", "warning");
    }

    function workbookChanges() {
        const changes = {};
        const ratings = {};
        Object.entries(state.sheets).forEach(([sheetName, sheet]) => {
            const cells = {};
            const assessed = {};
            sheet.rows.forEach((row, rowIndex) => {
                row.sourceCells.forEach((value, column) => {
                    if (value !== sheet.original[rowIndex][column]) cells[`${window.XLSX.utils.encode_col(column)}${rowIndex + 1}`] = value;
                });
                if (row.rating || row.evidence) assessed[String(rowIndex + 1)] = { rating: row.rating, evidence: row.evidence };
            });
            if (Object.keys(cells).length) changes[sheetName] = cells;
            if (Object.keys(assessed).length) ratings[sheetName] = assessed;
        });
        return { changes, ratings };
    }

    function renderAssignmentStatus() {
        if (!elements.assignmentSelect) return;
        const assignments = state.assignments.filter(item => item.template_file === state.fileName);
        elements.assignmentSelect.innerHTML = `<option value="">Unassigned draft</option>${assignments.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.assessment_name)} · ${escapeHtml(item.assigned_to)} · ${escapeHtml(item.status)}</option>`).join("")}`;
        if (!state.assignmentId && assignments.length === 1 && !state.auditId && !assignments[0].workbook_audit_id) state.assignmentId = String(assignments[0].id);
        elements.assignmentSelect.value = state.assignmentId || "";
        elements.assignmentSelect.disabled = state.submitted || state.historical || Boolean(state.auditId && state.assignmentId);
        const selected = assignments.find(item => String(item.id) === String(state.assignmentId));
        elements.assignmentStatus.textContent = selected
            ? `Assigned to ${selected.assigned_to} · ${String(selected.status).replaceAll("_", " ")} · ${selected.progress_percent || 0}% completed · ${selected.pending_items ?? selected.question_count ?? 0} pending items · edited by ${selected.edited_by || "not yet edited"}`
            : "No assignment selected.";
        const selectedFile = elements.catalog.querySelector("#secumatTemplateChoice")?.value;
        if (selectedFile === state.fileName) handleCatalogChange({ target: elements.catalog.querySelector("#secumatTemplateChoice") });
    }

    async function loadAssignments() {
        try {
            const response = await fetch("/api/audit_assignments");
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || `Assignment request failed (${response.status})`);
            state.assignments = data.assignments || [];
            if (!state.assignmentId && state.fileName) {
                const queryId = new URLSearchParams(location.search).get("assignmentId");
                if (state.assignments.some(item => String(item.id) === queryId && item.template_file === state.fileName)) state.assignmentId = queryId;
            }
            renderAssignmentStatus();
        } catch (error) {
            elements.assignmentStatus.textContent = `Could not load assignments: ${error.message}`;
        }
    }

    async function assignSelectedTemplate() {
        const fileName = elements.catalog.querySelector("#secumatTemplateChoice").value;
        const assignee = elements.catalog.querySelector("#secumatTemplateAssignee").value.trim();
        const status = elements.catalog.querySelector("#secumatTemplateStatus");
        if (!isSpreadsheet(fileName) || !assignee) { status.textContent = "Select a spreadsheet and enter an assignee."; return; }
        try {
            const response = await fetch("/api/audit_assignments", { method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ template_file: fileName, assessment_name: fileName.replace(/\.[^.]+$/, ""), assigned_to: assignee,
                    assigned_to_type: elements.catalog.querySelector("#secumatTemplateAssigneeType").value }) });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || `Assignment failed (${response.status})`);
            if (state.fileName === fileName && !state.auditId) state.assignmentId = String(data.assignment.id);
            await loadAssignments();
            window.loadAuditAssignments?.();
            status.textContent = `Assigned to ${assignee} · ${data.assignment.question_count} items pending. Open the workbook to review.`;
        } catch (error) {
            status.textContent = `Could not assign workbook: ${error.message}`;
        }
    }

    async function refreshAuditRegister() {
        if (!elements.historyBody) return;
        try {
            const response = await fetch("/api/audit/workbooks");
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || `History request failed (${response.status})`);
            elements.historyBody.innerHTML = data.history.map(item => `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.source)}</td><td>v${item.version}</td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(item.edited_by)}</td><td>${escapeHtml(new Date(item.updated_at).toLocaleString())}</td><td><button type="button" class="secumat-resource-load" data-open-workbook="${escapeHtml(item.source)}" data-open-version="${escapeHtml(item.id)}">Open</button></td></tr>`).join("") || `<tr><td colspan="7">No workbook audits saved yet.</td></tr>`;
        } catch (error) {
            elements.historyBody.innerHTML = `<tr><td colspan="7">${escapeHtml(error.message)}</td></tr>`;
        }
    }

    async function refreshHistory() {
        try {
            const response = await fetch(`/api/audit/workbooks?source=${encodeURIComponent(state.fileName)}`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || `History request failed (${response.status})`);
            const latest = new Map();
            data.history.forEach(item => { if (!latest.has(item.audit_id)) latest.set(item.audit_id, item); });
            elements.history.innerHTML = `<option value="">New audit draft</option>${[...latest.values()].map(item => `<option value="${escapeHtml(item.id)}" ${item.audit_id === state.auditId ? "selected" : ""}>${escapeHtml(item.name)} · v${item.version} · ${escapeHtml(item.status)}</option>`).join("")}`;
            elements.versions.innerHTML = data.history.filter(item => item.audit_id === state.auditId).map(item => `<option value="${escapeHtml(item.id)}" ${item.version === state.version ? "selected" : ""}>v${item.version} · ${escapeHtml(item.status)} · ${escapeHtml(item.edited_by)} · ${escapeHtml(new Date(item.updated_at).toLocaleString())}</option>`).join("");
            elements.versions.disabled = !state.auditId;
            return latest.get(state.auditId);
        } catch (error) {
            setStatus(`Could not load audit history: ${error.message}`, "error");
        }
    }

    function ensureWorkbookRow(sheet, rowIndex) {
        while (sheet.rows.length <= rowIndex) {
            const rowNumber = sheet.rows.length + 1;
            sheet.original.push(sheet.headers.map(() => ""));
            sheet.rows.push({ id: `row-${rowNumber}`, reference: String(rowNumber), section: "", question: "", rating: "", evidence: "", sourceCells: sheet.headers.map(() => "") });
        }
        return sheet.rows[rowIndex];
    }

    function applyRevision(revision) {
        Object.entries(state.sheets).forEach(([sheetName, sheet]) => {
            sheet.rows.length = sheet.baseRowCount;
            sheet.original.length = sheet.baseRowCount;
            sheet.rows.forEach((row, index) => {
                row.sourceCells = [...sheet.original[index]];
                row.rating = "";
                row.evidence = "";
            });
            Object.entries(revision?.changes?.[sheetName] || {}).forEach(([address, value]) => {
                const cell = window.XLSX.utils.decode_cell(address);
                const row = ensureWorkbookRow(sheet, cell.r);
                if (row.sourceCells[cell.c] !== undefined) row.sourceCells[cell.c] = value;
            });
            Object.entries(revision?.ratings?.[sheetName] || {}).forEach(([rowNumber, assessment]) => {
                const row = ensureWorkbookRow(sheet, Number(rowNumber) - 1);
                row.rating = assessment.rating;
                row.evidence = assessment.evidence;
            });
        });
        state.auditId = revision?.audit_id || "";
        state.assignmentId = revision?.assignment_id ? String(revision.assignment_id) : "";
        state.auditName = revision?.name || "";
        elements.nameInput.value = state.auditName || state.fileName.replace(/\.[^.]+$/, "");
        state.version = revision?.version || 0;
        state.submitted = revision?.status === "submitted";
        state.historical = false;
        state.dirty = false;
        state.editing = false;
        elements.editButton.textContent = "Edit workbook";
        loadSheet(state.sheetName);
        renderAssignmentStatus();
    }

    async function loadRevision(versionId) {
        try {
            if (state.dirty) { setStatus("Save or discard workbook edits before opening another audit version.", "warning"); await refreshHistory(); return; }
            const response = await fetch(`/api/audit/workbooks/versions/${encodeURIComponent(versionId)}`);
            const data = await response.json();
            if (!response.ok || data.revision.source !== state.fileName) throw new Error(data.error || "Wrong workbook version");
            applyRevision(data.revision);
            const latest = await refreshHistory();
            await loadAssignments();
            state.historical = Boolean(latest && latest.version > state.version);
            renderQuestions();
            setStatus(`Loaded ${state.auditName} version ${state.version} · edited by ${data.revision.edited_by}${state.historical ? " · historical view (Save As to reuse)" : ""}.`, "success");
        } catch (error) {
            setStatus(`Could not load audit version: ${error.message}`, "error");
        }
    }

    async function saveQuestionnaire(mode) {
        if (!state.fileName || state.busy) return;
        const saveAs = mode === "save-as";
        if ((state.submitted || state.historical) && !saveAs) return;
        const name = elements.nameInput.value.trim();
        if (!name) { setStatus("Enter an audit name before saving.", "error"); elements.nameInput.focus(); return; }
        const { changes, ratings } = workbookChanges();
        const payload = { source: state.fileName, name: String(name).trim(), status: mode === "submit" ? "submitted" : "draft", expectedVersion: saveAs ? 0 : state.version, changes, ratings };
        if (!saveAs && state.auditId) payload.auditId = state.auditId;
        if (!saveAs && state.assignmentId) payload.assignmentId = state.assignmentId;
        state.busy = true;
        renderQuestions();
        try {
            const response = await fetch("/api/audit/workbooks", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || `Save failed (${response.status})`);
            applyRevision(data.revision);
            let cleanupWarning = "";
            try { Object.keys(state.sheets).forEach(sheet => localStorage.removeItem(`secumat.audit-questionnaire.v1:${state.fileName}:${sheet}`)); } catch { cleanupWarning = " Earlier browser-only data could not be cleared."; }
            await refreshHistory();
            await refreshAuditRegister();
            await loadAssignments();
            window.loadAuditAssignments?.();
            setStatus(`${state.auditName} ${state.submitted ? "submitted" : "saved as draft"} · version ${state.version} · edited by ${data.revision.edited_by}.${cleanupWarning}`, cleanupWarning ? "warning" : "success");
        } catch (error) {
            setStatus(`Could not save audit: ${error.message}`, "error");
        } finally {
            state.busy = false;
            renderQuestions();
        }
    }

    function exportQuestionnaire() {
        if (!state.workbookBytes || !state.fileName) return;
        const workbook = window.XLSX.read(state.workbookBytes, { type: "array" });
        const { changes } = workbookChanges();
        Object.entries(changes).forEach(([sheet, cells]) => Object.entries(cells).forEach(([address, value]) => {
            workbook.Sheets[sheet][address] = { t: "s", v: value };
            const range = window.XLSX.utils.decode_range(workbook.Sheets[sheet]["!ref"] || "A1");
            const cell = window.XLSX.utils.decode_cell(address);
            range.e.r = Math.max(range.e.r, cell.r);
            range.e.c = Math.max(range.e.c, cell.c);
            workbook.Sheets[sheet]["!ref"] = window.XLSX.utils.encode_range(range);
        }));
        const reviewSheetName = "SECUMAT Review";
        if (workbook.Sheets[reviewSheetName]) {
            delete workbook.Sheets[reviewSheetName];
            workbook.SheetNames = workbook.SheetNames.filter(name => name !== reviewSheetName);
        }
        const rows = [["Sheet", "Excel row", "Rating", "Score (%)", "Evidence / Reviewer Notes"]];
        Object.entries(state.sheets).forEach(([sheetName, sheet]) => sheet.rows.forEach((item, index) => {
            if (!item.rating && !item.evidence) return;
            const score = item.rating ? ratingScores[item.rating] : "";
            rows.push([sheetName, index + 1, item.rating || "Not rated", score === null ? "N/A" : score, item.evidence]);
        }));
        window.XLSX.utils.book_append_sheet(workbook, window.XLSX.utils.aoa_to_sheet(rows), reviewSheetName);
        const exportName = state.fileName.replace(/\.(xlsx|xls|csv)$/i, "_reviewed.xlsx");
        window.XLSX.writeFile(workbook, exportName);
        setStatus(`Exported ${exportName} with edited cells and review notes.`, "success");
    }

    function handleCatalogClick(event) {
        if (event.target.closest("#secumatTemplateLoad")) {
            const fileName = elements.catalog.querySelector("#secumatTemplateChoice").value;
            const matches = state.assignments.filter(item => item.template_file === fileName && item.workbook_audit_id);
            if (matches.length === 1) openAssignment(matches[0].id, fileName);
            else loadQuestionnaire(fileName);
        }
        if (event.target.closest("#secumatTemplateAssign")) assignSelectedTemplate();
    }

    function handleCatalogChange(event) {
        if (event.target.id !== "secumatTemplateChoice") return;
        const fileName = event.target.value;
        const spreadsheet = isSpreadsheet(fileName);
        elements.catalog.querySelector("#secumatTemplateLoad").disabled = !spreadsheet;
        elements.catalog.querySelector("#secumatTemplateAssign").disabled = !spreadsheet;
        const excelLink = elements.catalog.querySelector("#secumatTemplateExcel");
        const editorLink = elements.catalog.querySelector("#secumatTemplateWindow");
        excelLink.href = fileName ? resourceUrl(fileName) : "#";
        excelLink.setAttribute("aria-disabled", String(!fileName));
        const matching = state.assignments.filter(item => item.template_file === fileName);
        const assignmentId = state.fileName === fileName && state.assignmentId ? state.assignmentId : matching.length === 1 ? matching[0].id : "";
        editorLink.href = spreadsheet ? `dashboard.html?workbook=${encodeURIComponent(fileName)}${assignmentId ? `&assignmentId=${encodeURIComponent(assignmentId)}` : ""}` : "#";
        editorLink.setAttribute("aria-disabled", String(!spreadsheet));
    }

    async function openAssignment(assignmentId, fileName) {
        if (state.dirty) { setStatus("Save or discard workbook edits before opening another assignment.", "warning"); return; }
        window.showSecumatPage?.("questionnaires");
        elements.catalog.querySelector("#secumatTemplateChoice").value = fileName;
        handleCatalogChange({ target: elements.catalog.querySelector("#secumatTemplateChoice") });
        await loadQuestionnaire(fileName);
        const response = await fetch(`/api/audit/workbooks?source=${encodeURIComponent(fileName)}`);
        const data = await response.json();
        const revision = (data.history || []).find(item => String(item.assignment_id) === String(assignmentId));
        if (revision) await loadRevision(revision.id);
        else {
            state.assignmentId = String(assignmentId);
            renderAssignmentStatus();
        }
    }

    function handleWorkbenchClick(event) {
        if (event.target.closest("#secumatQuestionnaireEdit")) {
            state.editing = !state.editing;
            elements.editButton.textContent = state.editing ? "View workbook" : "Edit workbook";
            renderQuestions();
            return;
        }
        if (event.target.closest("#secumatQuestionnaireSave")) {
            saveQuestionnaire("draft");
            return;
        }
        if (event.target.closest("#secumatQuestionnaireSaveAs")) {
            saveQuestionnaire("save-as");
            return;
        }
        if (event.target.closest("#secumatQuestionnaireSubmit")) {
            elements.submitDialog.showModal();
            return;
        }
        if (event.target.closest("#secumatWorkbookConfirmSubmit")) {
            elements.submitDialog.close();
            saveQuestionnaire("submit");
            return;
        }
        if (event.target.closest("#secumatWorkbookCancelSubmit")) {
            elements.submitDialog.close();
            return;
        }
        if (event.target.closest("#secumatQuestionnaireExport")) {
            exportQuestionnaire();
            return;
        }
        if (event.target.closest("#secumatWorkbookDiscard")) {
            const currentVersionId = elements.versions.value;
            state.dirty = false;
            if (currentVersionId) loadRevision(currentVersionId);
            else loadQuestionnaire(state.fileName);
            return;
        }
        const sheetTab = event.target.closest("[data-workbook-sheet]");
        if (sheetTab) {
            loadSheet(sheetTab.dataset.workbookSheet);
            return;
        }
        const pageButton = event.target.closest("[data-question-page]");
        if (pageButton) {
            state.page += pageButton.dataset.questionPage === "next" ? 1 : -1;
            renderQuestions();
            return;
        }
    }

    function handleWorkbenchInput(event) {
        if (event.target === elements.search) {
            state.search = elements.search.value;
            state.page = 0;
            renderQuestions();
            return;
        }
        const rowNumber = Number(event.target.dataset.row);
        const item = state.questions[rowNumber - 1];
        if (!item || !state.editing || state.submitted) return;
        if (event.target.dataset.column !== undefined) {
            item.sourceCells[Number(event.target.dataset.column)] = event.target.value;
        } else if (event.target.dataset.field === "rating" || event.target.dataset.field === "evidence") {
            item[event.target.dataset.field] = event.target.value;
        } else {
            return;
        }
        markDirty();
        renderSummary();
    }

    function handleWorkbenchChange(event) {
        if (event.target === elements.sheetSelect) {
            loadSheet(elements.sheetSelect.value);
            return;
        }
        if (event.target === elements.nameInput) {
            if (!state.submitted && !state.historical && elements.nameInput.value.trim() !== state.auditName) markDirty();
            return;
        }
        if (event.target === elements.assignmentSelect) {
            state.assignmentId = elements.assignmentSelect.value;
            renderAssignmentStatus();
            if (!state.submitted && !state.historical) markDirty();
            return;
        }
        if (event.target === elements.history || event.target === elements.versions) {
            if (event.target.value) loadRevision(event.target.value);
            else if (event.target === elements.history && !state.dirty) {
                applyRevision(null);
                refreshHistory();
            } else {
                setStatus("Save or discard workbook edits before opening another audit.", "warning");
                refreshHistory();
            }
            return;
        }
        if (event.target.dataset.field === "rating") {
            handleWorkbenchInput(event);
            renderQuestions();
            return;
        }
        handleWorkbenchInput(event);
    }

    function initialize() {
        if (!elements.catalog || !elements.workspace) return;
        loadCatalog().then(() => {
            const selected = new URLSearchParams(location.search).get("workbook");
            if (!selected || !resources.includes(selected) || !isSpreadsheet(selected)) return;
            elements.catalog.querySelector("#secumatTemplateChoice").value = selected;
            handleCatalogChange({ target: elements.catalog.querySelector("#secumatTemplateChoice") });
            const assignmentId = new URLSearchParams(location.search).get("assignmentId");
            if (assignmentId) openAssignment(assignmentId, selected);
            else { window.showSecumatPage?.("questionnaires"); loadQuestionnaire(selected); }
        });
        loadAssignments();
        refreshAuditRegister();
        elements.catalog.addEventListener("click", handleCatalogClick);
        elements.catalog.addEventListener("change", handleCatalogChange);
        document.getElementById("auditAssignmentsBody")?.addEventListener("click", event => {
            const button = event.target.closest("[data-workbook-assignment]");
            if (button) openAssignment(button.dataset.workbookAssignment, button.dataset.workbookFile);
        });
        elements.historyBody?.addEventListener("click", async event => {
            const button = event.target.closest("[data-open-version]");
            if (!button) return;
            if (state.dirty) { setStatus("Save or discard workbook edits before opening another audit.", "warning"); return; }
            window.showSecumatPage?.("questionnaires");
            await loadQuestionnaire(button.dataset.openWorkbook);
            if (state.fileName === button.dataset.openWorkbook) await loadRevision(button.dataset.openVersion);
        });
        elements.workspace.addEventListener("click", handleWorkbenchClick);
        elements.workspace.addEventListener("input", handleWorkbenchInput);
        elements.workspace.addEventListener("change", handleWorkbenchChange);
        window.SECUMAT_WORKBOOK = { openAssignment };
    }

    initialize();
})();
