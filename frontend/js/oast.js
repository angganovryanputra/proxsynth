/**
 * Proxsynth - OAST (Out-of-Band Application Security Testing) Component
 * Features: Multi-protocol listeners (HTTP, DNS, LDAP/JNDI), Token Generator,
 * and Autonomous Multi-Protocol Canary Sprayer (P2).
 */

window.OastModule = {
  data() {
    return {
      oastEvents: [],
      latestOastTokenData: null,
      oastVulnTypeInput: 'BLIND_SSRF',
      oastDescriptionInput: 'AI Agent Blind Vulnerability Probe',
      isGeneratingOast: false,
      oastSearchQuery: '',
      oastProtocols: { http: { active: true }, dns: { active: false }, ldap: { active: false } },

      // P2: Autonomous Canary Sprayer UI State
      showOastSprayModal: false,
      isSprayingCanaries: false,
      oastSprayForm: {
        target_url: '',
        method: 'GET',
        headers_raw: '',
        body: '',
        target_params: '',
        vuln_types: ['ssrf', 'dns', 'log4j']
      },
      oastSprayResult: null
    };
  },

  methods: {
    async fetchProtocolsStatus() {
      try {
        const resp = await fetch('/api/oast/protocols/status');
        if (resp.ok) {
          this.oastProtocols = await resp.json();
        }
      } catch (err) {
        console.error('Failed to fetch protocol status:', err);
      }
    },

    async fetchOastEvents() {
      await this.fetchProtocolsStatus();
      const proj = this.selectedProject === 'ALL' ? 'all' : (this.selectedProject || 'all');
      try {
        const resp = await fetch(`/api/oast/events?project=${encodeURIComponent(proj)}&limit=100`);
        if (resp.ok) {
          const data = await resp.json();
          this.oastEvents = data.events || [];
          this.$nextTick(() => {
            if (window.lucide) lucide.createIcons();
          });
        }
      } catch (err) {
        console.error('Failed to fetch OAST events:', err);
      }
    },

    async generateNewOastToken() {
      let proj = this.selectedProject;
      if (!proj || proj === 'ALL') {
        proj = typeof this.resolveConcreteProject === 'function'
          ? this.resolveConcreteProject('Select target project to generate this OAST canary token:')
          : prompt('Please enter target project for this token:', 'default');
        if (!proj) return;
      }
      this.isGeneratingOast = true;
      try {
        const resp = await fetch('/api/oast/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            project: proj,
            vuln_type: this.oastVulnTypeInput,
            description: this.oastDescriptionInput
          })
        });
        if (resp.ok) {
          this.latestOastTokenData = await resp.json();
          this.showToast({
            title: 'OAST Token Generated',
            message: `Token ${this.latestOastTokenData.token} ready for injection into '${proj}'!`
          });
        }
      } catch (err) {
        alert('Failed to generate OAST token: ' + err);
      } finally {
        this.isGeneratingOast = false;
      }
    },

    async triggerOastCanarySprayUI() {
      if (!this.oastSprayForm.target_url.trim()) {
        alert('Please enter a valid target URL to spray.');
        return;
      }

      let proj = this.selectedProject;
      if (!proj || proj === 'ALL') {
        proj = typeof this.resolveConcreteProject === 'function'
          ? this.resolveConcreteProject('Select target project for OAST canary spraying:')
          : prompt('Please enter target project for canary spray:', 'default');
        if (!proj) return;
      }

      this.isSprayingCanaries = true;
      this.oastSprayResult = null;

      let parsedHeaders = null;
      if (this.oastSprayForm.headers_raw.trim()) {
        try {
          parsedHeaders = JSON.parse(this.oastSprayForm.headers_raw.trim());
        } catch (e) {
          alert('Headers must be valid JSON: ' + e);
          this.isSprayingCanaries = false;
          return;
        }
      }

      let parsedParams = null;
      if (this.oastSprayForm.target_params.trim()) {
        parsedParams = this.oastSprayForm.target_params.split(',').map(s => s.trim()).filter(Boolean);
      }

      try {
        const resp = await fetch('/api/oast/spray', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_url: this.oastSprayForm.target_url.trim(),
            method: this.oastSprayForm.method,
            headers: parsedHeaders,
            body: this.oastSprayForm.body,
            target_params: parsedParams,
            vuln_types: this.oastSprayForm.vuln_types,
            project: proj
          })
        });

        if (resp.ok) {
          this.oastSprayResult = await resp.json();
          const count = this.oastSprayResult.total_canaries_sprayed || 0;
          const hits = this.oastSprayResult.confirmed_vulnerabilities_count || 0;
          this.showToast({
            title: 'Canary Spray Finished',
            message: `Sprayed ${count} canaries across ${this.oastSprayResult.parameters_tested.length} parameters. Immediate hits: ${hits}`
          });
          await this.fetchOastEvents();
        } else {
          const err = await resp.text();
          alert('Spray error: ' + err);
        }
      } catch (err) {
        alert('Spray failed: ' + err);
      } finally {
        this.isSprayingCanaries = false;
      }
    },

    async clearAllOastEvents() {
      if (!confirm('Clear all recorded out-of-band callback events?')) return;
      const proj = this.selectedProject;
      try {
        const resp = await fetch(`/api/oast/events?project=${encodeURIComponent(proj)}`, {
          method: 'DELETE'
        });
        if (resp.ok) {
          this.oastEvents = [];
          this.showToast({
            title: 'OAST Cleared',
            message: 'Out-of-band events ledger wiped clean.'
          });
        }
      } catch (err) {
        console.error('Failed to clear OAST events:', err);
      }
    },

    filteredOastEvents() {
      if (!this.oastEvents) return [];
      const q = (this.oastSearchQuery || '').toLowerCase().trim();
      if (!q) return this.oastEvents;

      return this.oastEvents.filter(ev => {
        return (ev.token && ev.token.toLowerCase().includes(q)) ||
          (ev.client_ip && ev.client_ip.includes(q)) ||
          (ev.method && ev.method.toLowerCase().includes(q)) ||
          (ev.path && ev.path.toLowerCase().includes(q)) ||
          (ev.request_body && ev.request_body.toLowerCase().includes(q));
      });
    }
  }
};
