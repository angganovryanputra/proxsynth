/**
 * Proxsynth - Attack Surface Knowledge Graph Component
 */

window.AttackSurfaceModule = {
  data() {
    return {
      attackSurfaceData: { summary: {}, assets: [] },
      attackSurfaceSearch: '',
      attackSurfaceStatusFilter: 'ALL',
      selectedAssetId: null,
      showAddAssetModal: false,
      newAssetForm: {
        host: '',
        ip: '',
        os_info: '',
        tags: '',
        notes: ''
      },
      showAddServiceModal: false,
      newServiceForm: {
        host: '',
        port: 80,
        protocol: 'tcp',
        service_name: 'http',
        banner: '',
        state: 'open'
      },
      attackPathsData: null,
      showAttackPathsModal: false,
      isGeneratingAttackPaths: false,
      showPocModal: false,
      pocModalData: null,
      pocActiveTab: 'python', // 'python' | 'curl' | 'dossier'
      isGeneratingPoc: false,
      isInferringRoutes: false
    };
  },

  methods: {
    async fetchAttackSurface() {
      const proj = this.selectedProject || 'default';
      try {
        const resp = await fetch(`/api/targets/graph?project=${encodeURIComponent(proj)}`);
        if (resp.ok) {
          this.attackSurfaceData = await resp.json();
          this.$nextTick(() => {
            if (window.lucide) lucide.createIcons();
          });
        }
      } catch (err) {
        console.error('Failed to fetch attack surface graph:', err);
      }
    },

    filteredAssets() {
      if (!this.attackSurfaceData || !this.attackSurfaceData.assets) return [];
      const q = (this.attackSurfaceSearch || '').toLowerCase().trim();
      const statusF = this.attackSurfaceStatusFilter || 'ALL';

      return this.attackSurfaceData.assets.filter(a => {
        const hostMatch = !q || (a.host && a.host.toLowerCase().includes(q)) || (a.ip && a.ip.includes(q)) || (a.os_info && a.os_info.toLowerCase().includes(q));
        if (!hostMatch) return false;

        if (statusF !== 'ALL') {
          const hasMatchingStatus = (a.endpoints || []).some(ep => ep.tested_status === statusF);
          if (!hasMatchingStatus) return false;
        }
        return true;
      });
    },

    async saveNewAsset() {
      if (!this.newAssetForm.host) {
        alert('Hostname/Domain is required.');
        return;
      }
      let proj = this.selectedProject;
      if (!proj || proj === 'ALL') {
        proj = typeof this.resolveConcreteProject === 'function'
          ? this.resolveConcreteProject('Select target project to register this asset:')
          : prompt('Please enter target project for this asset:', 'default');
        if (!proj) return;
      }
      try {
        const payload = {
          project: proj,
          host: this.newAssetForm.host,
          ip: this.newAssetForm.ip,
          os_info: this.newAssetForm.os_info,
          tags: this.newAssetForm.tags ? this.newAssetForm.tags.split(',').map(t => t.trim()) : [],
          notes: this.newAssetForm.notes
        };
        const resp = await fetch('/api/targets/assets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (resp.ok) {
          this.showAddAssetModal = false;
          this.newAssetForm = { host: '', ip: '', os_info: '', tags: '', notes: '' };
          await this.fetchAttackSurface();
        }
      } catch (err) {
        alert('Failed to save asset: ' + err);
      }
    },

    async saveNewService() {
      if (!this.newServiceForm.host || !this.newServiceForm.port) {
        alert('Host and Port are required.');
        return;
      }
      let proj = this.selectedProject;
      if (!proj || proj === 'ALL') {
        proj = typeof this.resolveConcreteProject === 'function'
          ? this.resolveConcreteProject('Select target project to register this service:')
          : prompt('Please enter target project for this service:', 'default');
        if (!proj) return;
      }
      try {
        const payload = {
          project: proj,
          host: this.newServiceForm.host,
          port: parseInt(this.newServiceForm.port),
          protocol: this.newServiceForm.protocol || 'tcp',
          service_name: this.newServiceForm.service_name || 'unknown',
          banner: this.newServiceForm.banner || '',
          state: this.newServiceForm.state || 'open'
        };
        const resp = await fetch('/api/targets/services', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (resp.ok) {
          this.showAddServiceModal = false;
          await this.fetchAttackSurface();
        }
      } catch (err) {
        alert('Failed to save service: ' + err);
      }
    },

    async updateEndpointStatus(endpointId, newStatus) {
      try {
        const resp = await fetch(`/api/targets/endpoints/${endpointId}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tested_status: newStatus })
        });
        if (resp.ok) {
          await this.fetchAttackSurface();
        }
      } catch (err) {
        console.error('Failed to update endpoint status:', err);
      }
    },

    async deleteAsset(assetId) {
      if (!confirm(`Are you sure you want to delete asset #${assetId} and all associated services/endpoints?`)) return;
      try {
        const resp = await fetch(`/api/targets/assets/${assetId}`, { method: 'DELETE' });
        if (resp.ok) {
          if (this.showToast) {
            this.showToast({ title: 'Asset Deleted', message: `Target asset #${assetId} removed.` });
          }
          await this.fetchAttackSurface();
        }
      } catch (err) {
        console.error('Failed to delete asset:', err);
      }
    },

    async deleteEndpoint(endpointId) {
      if (!confirm(`Are you sure you want to delete endpoint #${endpointId}?`)) return;
      try {
        const resp = await fetch(`/api/targets/endpoints/${endpointId}`, { method: 'DELETE' });
        if (resp.ok) {
          if (this.showToast) {
            this.showToast({ title: 'Endpoint Deleted', message: `Endpoint #${endpointId} removed from attack surface.` });
          }
          await this.fetchAttackSurface();
        }
      } catch (err) {
        console.error('Failed to delete endpoint:', err);
      }
    },

    async deleteService(serviceId) {
      if (!confirm(`Are you sure you want to remove service #${serviceId}?`)) return;
      try {
        const resp = await fetch(`/api/targets/services/${serviceId}`, { method: 'DELETE' });
        if (resp.ok) {
          if (this.showToast) {
            this.showToast({ title: 'Service Removed', message: `Port/Service #${serviceId} removed.` });
          }
          await this.fetchAttackSurface();
        }
      } catch (err) {
        console.error('Failed to delete service:', err);
      }
    },

    async clearAttackSurface() {
      const proj = this.selectedProject || 'default';
      const promptText = proj === 'ALL'
        ? 'Are you sure you want to CLEAR ALL attack surface assets across ALL projects?'
        : `Are you sure you want to CLEAR ALL attack surface assets for project '${proj}'?`;
      if (!confirm(promptText)) return;

      try {
        const resp = await fetch(`/api/targets/graph?project=${encodeURIComponent(proj)}`, { method: 'DELETE' });
        if (resp.ok) {
          const res = await resp.json();
          if (this.showToast) {
            this.showToast({
              title: 'Attack Surface Cleared',
              message: `Cleared ${res.deleted_assets || 0} assets from attack surface.`
            });
          }
          await this.fetchAttackSurface();
        }
      } catch (err) {
        alert('Failed to clear attack surface: ' + err);
      }
    },

    sendEndpointToRepeater(ep) {
      if (!ep || !ep.url) return;
      this.currentAppTab = 'repeater';
      const activeTab = this.activeRepeaterTab;
      if (activeTab) {
        activeTab.url = ep.url;
        activeTab.method = ep.method || 'GET';
      }
      this.$nextTick(() => {
        if (window.lucide) lucide.createIcons();
      });
    },

    async inferHiddenEndpoints() {
      let proj = this.selectedProject;
      if (!proj || proj === 'ALL') {
        proj = typeof this.resolveConcreteProject === 'function'
          ? this.resolveConcreteProject('Select target project to infer hidden endpoints:')
          : prompt('Please enter target project to infer routes:', 'default');
        if (!proj) return;
      }
      this.isInferringRoutes = true;
      try {
        const resp = await fetch(`/api/attack-surface/infer?project=${encodeURIComponent(proj)}`, { method: 'POST' });
        if (resp.ok) {
          const data = await resp.json();
          if (this.showToast) {
            this.showToast({
              title: 'Endpoints Inferred',
              message: `Successfully synthesized and mapped ${data.inferred_count || 0} speculative API routes for '${proj}'!`
            });
          }
          await this.fetchAttackSurface();
        } else {
          alert('Failed to infer endpoints');
        }
      } catch (err) {
        alert('Failed to infer endpoints: ' + err);
      } finally {
        this.isInferringRoutes = false;
      }
    },

    async viewAttackPaths() {
      this.isGeneratingAttackPaths = true;
      const proj = this.selectedProject === 'ALL' ? 'all' : (this.selectedProject || 'default');
      try {
        const resp = await fetch(`/api/attack-path?project=${encodeURIComponent(proj)}`);
        if (resp.ok) {
          this.attackPathsData = await resp.json();
          this.showAttackPathsModal = true;
          this.$nextTick(() => {
            if (window.lucide) lucide.createIcons();
          });
        }
      } catch (err) {
        alert('Failed to generate attack paths: ' + err);
      } finally {
        this.isGeneratingAttackPaths = false;
      }
    },

    async generateFindingDossier(findingId) {
      this.isGeneratingPoc = true;
      try {
        const resp = await fetch(`/api/findings/${findingId}/dossier`);
        if (resp.ok) {
          this.pocModalData = await resp.json();
          this.pocActiveTab = 'python';
          this.showPocModal = true;
          this.$nextTick(() => {
            if (window.lucide) lucide.createIcons();
          });
        } else {
          alert('Finding not found or failed to generate dossier.');
        }
      } catch (err) {
        alert('Failed to generate finding dossier: ' + err);
      } finally {
        this.isGeneratingPoc = false;
      }
    }
  }
};
