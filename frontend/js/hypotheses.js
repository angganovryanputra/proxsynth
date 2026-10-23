/**
 * Proxsynth - Attack Hypothesis Ledger & Agent Working Memory (P3)
 * Provides real-time visibility into the AI Agent's hypothesis testing lifecycle:
 * PLANNED -> TESTING -> CONFIRMED -> DISPROVEN -> BLOCKED
 */

window.HypothesesModule = {
  data() {
    return {
      hypothesesList: [],
      hypothesisAgenda: {
        total_hypotheses: 0,
        planned_count: 0,
        in_progress_count: 0,
        confirmed_findings_count: 0,
        disproven_count: 0,
        blocked_count: 0,
        untested_agenda: []
      },
      hypothesisFilterStatus: 'ALL',
      hypothesisSearchQuery: '',
      isLoadingHypotheses: false,
      showNewHypothesisModal: false,
      isSubmittingHypothesis: false,
      newHypothesisForm: {
        target: '',
        vuln_type: 'BOLA',
        hypothesis: '',
        status: 'PLANNED',
        evidence_notes: '',
        agent_id: 'human_operator'
      },
      selectedHypothesisDetail: null
    };
  },

  methods: {
    async fetchHypotheses() {
      this.isLoadingHypotheses = true;
      const proj = this.selectedProject === 'ALL' ? 'all' : (this.selectedProject || 'all');
      try {
        const [hypResp, agendaResp] = await Promise.all([
          fetch(`/api/hypotheses?project=${encodeURIComponent(proj)}`),
          fetch(`/api/hypotheses/agenda?project=${encodeURIComponent(proj)}`)
        ]);

        if (hypResp.ok) {
          const hypData = await hypResp.json();
          this.hypothesesList = hypData.hypotheses || [];
        }

        if (agendaResp.ok) {
          this.hypothesisAgenda = await agendaResp.json();
        }

        this.$nextTick(() => {
          if (window.lucide) lucide.createIcons();
        });
      } catch (err) {
        console.error('Failed to fetch hypotheses ledger:', err);
      } finally {
        this.isLoadingHypotheses = false;
      }
    },

    async createHypothesisFromUI() {
      if (!this.newHypothesisForm.target.trim() || !this.newHypothesisForm.hypothesis.trim()) {
        alert('Please specify both a target and an attack hypothesis.');
        return;
      }

      let proj = this.selectedProject;
      if (!proj || proj === 'ALL') {
        proj = typeof this.resolveConcreteProject === 'function'
          ? this.resolveConcreteProject('Select target project to register this hypothesis:')
          : prompt('Please enter target project for this hypothesis:', 'default');
        if (!proj) return;
      }

      this.isSubmittingHypothesis = true;

      try {
        const resp = await fetch('/api/hypotheses', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            project: proj,
            target: this.newHypothesisForm.target.trim(),
            vuln_type: this.newHypothesisForm.vuln_type,
            hypothesis: this.newHypothesisForm.hypothesis.trim(),
            status: this.newHypothesisForm.status,
            evidence_notes: this.newHypothesisForm.evidence_notes.trim(),
            agent_id: this.newHypothesisForm.agent_id || 'human_operator'
          })
        });

        if (resp.ok) {
          const created = await resp.json();
          this.showNewHypothesisModal = false;
          this.newHypothesisForm = {
            target: '',
            vuln_type: 'BOLA',
            hypothesis: '',
            status: 'PLANNED',
            evidence_notes: '',
            agent_id: 'human_operator'
          };
          this.showToast({
            title: 'Hypothesis Registered',
            message: `Recorded #${created.id} [${created.vuln_type}] on ${created.target} for '${proj}'`
          });
          await this.fetchHypotheses();
        } else {
          const err = await resp.text();
          alert('Failed to register hypothesis: ' + err);
        }
      } catch (err) {
        alert('Error: ' + err);
      } finally {
        this.isSubmittingHypothesis = false;
      }
    },

    async updateHypothesisStatusUI(hypId, newStatus, evidenceNotes = '') {
      const proj = this.selectedProject === 'ALL' ? 'all' : (this.selectedProject || 'default');
      try {
        const payload = { status: newStatus };
        if (evidenceNotes) payload.evidence_notes = evidenceNotes;

        const resp = await fetch(`/api/hypotheses/${hypId}?project=${encodeURIComponent(proj)}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        if (resp.ok) {
          const updated = await resp.json();
          this.showToast({
            title: `Hypothesis #${hypId} Updated`,
            message: `Status transitioned to ${newStatus}`
          });
          await this.fetchHypotheses();
        } else {
          const err = await resp.text();
          alert('Failed to update hypothesis: ' + err);
        }
      } catch (err) {
        console.error('Error updating hypothesis status:', err);
      }
    },

    async deleteHypothesisUI(hypId) {
      if (!confirm(`Delete hypothesis #${hypId} from agent working memory?`)) return;
      const proj = this.selectedProject === 'ALL' ? 'all' : (this.selectedProject || 'default');

      try {
        const resp = await fetch(`/api/hypotheses/${hypId}?project=${encodeURIComponent(proj)}`, {
          method: 'DELETE'
        });

        if (resp.ok) {
          this.showToast({
            title: 'Hypothesis Deleted',
            message: `Hypothesis #${hypId} removed from working memory.`
          });
          if (this.selectedHypothesisDetail && this.selectedHypothesisDetail.id === hypId) {
            this.selectedHypothesisDetail = null;
          }
          await this.fetchHypotheses();
        }
      } catch (err) {
        console.error('Error deleting hypothesis:', err);
      }
    },

    handleHypothesisWsEvent(msg) {
      const currentProj = this.selectedProject || 'default';
      const eventProj = msg.project || (msg.hypothesis && msg.hypothesis.project);

      if (currentProj !== 'ALL' && eventProj && eventProj !== currentProj) {
        return;
      }

      if (msg.type === 'HYPOTHESIS_CREATED' && msg.hypothesis) {
        const hyp = msg.hypothesis;
        const existingIdx = this.hypothesesList.findIndex(h => h.id === hyp.id);
        if (existingIdx === -1) {
          this.hypothesesList.unshift(hyp);
        } else {
          this.hypothesesList.splice(existingIdx, 1, hyp);
        }
        this.showToast({
          title: `[AI Working Memory] New Hypothesis`,
          message: `${hyp.agent_id || 'Agent'}: [${hyp.vuln_type}] ${hyp.target}`
        });
        this.fetchHypotheses();
      } else if (msg.type === 'HYPOTHESIS_UPDATED' && msg.hypothesis) {
        const hyp = msg.hypothesis;
        const idx = this.hypothesesList.findIndex(h => h.id === hyp.id);
        if (idx !== -1) {
          this.hypothesesList.splice(idx, 1, hyp);
        }
        if (hyp.status === 'CONFIRMED') {
          this.showToast({
            title: `🏆 VULNERABILITY CONFIRMED!`,
            message: `[${hyp.vuln_type}] ${hyp.target} was confirmed by agent!`
          });
        }
        this.fetchHypotheses();
      } else if (msg.type === 'HYPOTHESIS_DELETED') {
        this.hypothesesList = this.hypothesesList.filter(h => h.id !== msg.id);
        this.fetchHypotheses();
      }

      this.$nextTick(() => {
        if (window.lucide) lucide.createIcons();
      });
    },

    filteredHypotheses() {
      if (!this.hypothesesList) return [];
      let list = this.hypothesesList;

      if (this.hypothesisFilterStatus && this.hypothesisFilterStatus !== 'ALL') {
        list = list.filter(h => (h.status || '').toUpperCase() === this.hypothesisFilterStatus);
      }

      const q = (this.hypothesisSearchQuery || '').toLowerCase().trim();
      if (q) {
        list = list.filter(h => {
          return (h.target && h.target.toLowerCase().includes(q)) ||
            (h.vuln_type && h.vuln_type.toLowerCase().includes(q)) ||
            (h.hypothesis && h.hypothesis.toLowerCase().includes(q)) ||
            (h.evidence_notes && h.evidence_notes.toLowerCase().includes(q)) ||
            (h.agent_id && h.agent_id.toLowerCase().includes(q));
        });
      }

      return list;
    },

    getHypothesisStatusBadge(status) {
      const s = (status || 'PLANNED').toUpperCase();
      switch (s) {
        case 'CONFIRMED':
          return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 ring-1 ring-emerald-500/30';
        case 'TESTING':
          return 'bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse';
        case 'DISPROVEN':
          return 'bg-slate-700/60 text-slate-400 border-slate-600/40';
        case 'BLOCKED':
          return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
        case 'PLANNED':
        default:
          return 'bg-sky-500/20 text-sky-300 border-sky-500/40';
      }
    }
  }
};
