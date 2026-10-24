import React, { useState, useEffect, useCallback } from 'react';
import {
  Sliders,
  AlertTriangle,
  Edit,
  RefreshCw,
  Power,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Spinner } from '../components/common/Spinner';
import { Modal } from '../components/common/Modal';
import { tauriCommands } from '../services/tauriCommands';
import type { DetectionRule, UpdateDetectionRuleInput } from '../types';

interface DetectionRulesPageProps {
  onAddToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const DetectionRulesPage: React.FC<DetectionRulesPageProps> = ({ onAddToast }) => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Edit Modal State
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);
  const [thresholdInput, setThresholdInput] = useState<string>('');
  const [windowInput, setWindowInput] = useState<string>('');
  const [cooldownInput, setCooldownInput] = useState<string>('');
  const [maxEvidenceInput, setMaxEvidenceInput] = useState<string>('');
  const [enabledInput, setEnabledInput] = useState<boolean>(true);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState<boolean>(false);

  // Disable Confirmation Modal State
  const [ruleToToggle, setRuleToToggle] = useState<DetectionRule | null>(null);

  const fetchRules = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const res = await tauriCommands.getDetectionRules();
      setRules(res);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const handleOpenEdit = (rule: DetectionRule) => {
    setEditingRule(rule);
    setThresholdInput(String(rule.threshold));
    setWindowInput(String(rule.window_duration_secs));
    setCooldownInput(rule.cooldown_secs != null ? String(rule.cooldown_secs) : '0');
    setMaxEvidenceInput(String(rule.max_evidence_ids));
    setEnabledInput(rule.enabled);
    setValidationError(null);
  };

  const handleSaveEdit = async () => {
    if (!editingRule) return;

    const threshold = parseInt(thresholdInput, 10);
    const windowSecs = parseInt(windowInput, 10);
    const cooldown = parseInt(cooldownInput, 10);
    const maxEvidence = parseInt(maxEvidenceInput, 10);

    if (isNaN(threshold) || threshold <= 0) {
      setValidationError('Threshold must be a valid positive integer greater than 0.');
      return;
    }
    if (isNaN(windowSecs) || windowSecs <= 0) {
      setValidationError('Observation window must be a positive number of seconds.');
      return;
    }
    if (isNaN(cooldown) || cooldown < 0) {
      setValidationError('Cooldown seconds must be 0 or a positive number.');
      return;
    }
    if (isNaN(maxEvidence) || maxEvidence <= 0) {
      setValidationError('Maximum evidence records must be at least 1.');
      return;
    }

    const input: UpdateDetectionRuleInput = {
      rule_id: editingRule.rule_id,
      enabled: enabledInput,
      threshold,
      window_duration_secs: windowSecs,
      cooldown_secs: cooldown > 0 ? cooldown : null,
      max_evidence_ids: maxEvidence,
    };

    setIsSaving(true);
    setValidationError(null);

    try {
      await tauriCommands.updateDetectionRule(input);
      onAddToast('success', `Detection rule ${editingRule.rule_id} updated successfully.`);
      setEditingRule(null);
      await fetchRules();
    } catch (err: unknown) {
      setValidationError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsSaving(false);
    }
  };

  const handleConfirmToggleDisable = async () => {
    if (!ruleToToggle) return;
    setIsSaving(true);

    try {
      await tauriCommands.updateDetectionRule({
        rule_id: ruleToToggle.rule_id,
        enabled: !ruleToToggle.enabled,
        threshold: ruleToToggle.threshold,
        window_duration_secs: ruleToToggle.window_duration_secs,
        cooldown_secs: ruleToToggle.cooldown_secs,
        max_evidence_ids: ruleToToggle.max_evidence_ids,
      });

      onAddToast(
        'info',
        `Detection rule ${ruleToToggle.rule_id} ${!ruleToToggle.enabled ? 'enabled' : 'disabled'}.`
      );
      setRuleToToggle(null);
      await fetchRules();
    } catch (err: unknown) {
      onAddToast('error', err instanceof Error ? err.message : String(err));
    } finally {
      setIsSaving(false);
    }
  };

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour12: false })}`;
    } catch {
      return ts;
    }
  };

  return (
    <div className="space-y-6">
      {/* Overview Card */}
      <Card bodyClassName="p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              <span>Authoritative Detection Rules</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Configuration governing real-time rolling-window correlation and threat heuristics.
              Changes persist in SQLite storage and are audited.
            </p>
          </div>

          <Button
            size="sm"
            variant="secondary"
            onClick={fetchRules}
            isLoading={isLoading}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh Rules
          </Button>
        </div>
      </Card>

      {errorMessage && (
        <div className="p-4 bg-red-950/60 border border-red-800/60 rounded-lg text-xs text-red-200">
          Failed to load rules: {errorMessage}
        </div>
      )}

      {isLoading ? (
        <Spinner label="Loading authoritative detection rules from Rust..." size="lg" />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {rules.map((rule) => {
            const isEnabled = rule.enabled;

            return (
              <Card
                key={rule.rule_id}
                title={
                  <div className="flex items-center gap-2 font-mono">
                    <span className="text-cyan-400 font-bold">{rule.rule_id}</span>
                    <span className="text-slate-400 font-normal text-xs">v{rule.rule_version}</span>
                  </div>
                }
                subtitle={rule.name}
                headerAction={
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                        isEnabled
                          ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                          : 'bg-red-950/60 text-red-400 border-red-800/60'
                      }`}
                    >
                      {isEnabled ? 'ENABLED' : 'DISABLED'}
                    </span>

                    <button
                      onClick={() => {
                        if (isEnabled) {
                          setRuleToToggle(rule);
                        } else {
                          // Enabling doesn't require high-risk confirmation modal
                          tauriCommands
                            .updateDetectionRule({
                              rule_id: rule.rule_id,
                              enabled: true,
                              threshold: rule.threshold,
                              window_duration_secs: rule.window_duration_secs,
                              cooldown_secs: rule.cooldown_secs,
                              max_evidence_ids: rule.max_evidence_ids,
                            })
                            .then(() => {
                              onAddToast('success', `Rule ${rule.rule_id} enabled.`);
                              fetchRules();
                            })
                            .catch((e) => onAddToast('error', e.message));
                        }
                      }}
                      className={`p-1.5 rounded-md border transition-colors ${
                        isEnabled
                          ? 'bg-slate-800 hover:bg-red-950/50 text-slate-300 hover:text-red-400 border-slate-700 hover:border-red-800'
                          : 'bg-slate-800 hover:bg-emerald-950/50 text-slate-300 hover:text-emerald-400 border-slate-700 hover:border-emerald-800'
                      }`}
                      title={isEnabled ? 'Disable Rule' : 'Enable Rule'}
                      aria-label={`Toggle rule ${rule.rule_id}`}
                    >
                      <Power className="w-3.5 h-3.5" />
                    </button>
                  </div>
                }
                bodyClassName="space-y-4 text-xs"
                footer={
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>Last updated: {formatTimestamp(rule.updated_at)}</span>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => handleOpenEdit(rule)}
                      leftIcon={<Edit className="w-3 h-3" />}
                    >
                      Edit Config
                    </Button>
                  </div>
                }
              >
                <p className="text-slate-300 leading-relaxed text-xs">{rule.description}</p>

                {!isEnabled && (
                  <div className="p-2.5 rounded bg-amber-950/30 border border-amber-700/40 text-amber-300 flex items-center gap-2 text-[11px]">
                    <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
                    <span>Warning: Threat detection for this rule is currently suspended.</span>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3 bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/80 font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-sans">
                      Threshold
                    </span>
                    <span className="text-slate-100 font-bold text-sm">{rule.threshold}</span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-sans">
                      Observation Window
                    </span>
                    <span className="text-slate-100 font-bold text-sm">
                      {rule.window_duration_secs}s
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-sans">
                      Alert Cooldown
                    </span>
                    <span className="text-slate-300">
                      {rule.cooldown_secs != null ? `${rule.cooldown_secs}s` : 'None'}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase font-sans">
                      Max Evidence IDs
                    </span>
                    <span className="text-slate-300">{rule.max_evidence_ids}</span>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Edit Rule Configuration Modal */}
      <Modal
        isOpen={editingRule !== null}
        onClose={() => setEditingRule(null)}
        title={`Edit Rule Configuration (${editingRule?.rule_id})`}
        description="Fine-tune correlation thresholds and rolling window constraints"
        footer={
          <>
            <Button size="sm" variant="secondary" onClick={() => setEditingRule(null)} disabled={isSaving}>
              Cancel
            </Button>
            <Button size="sm" variant="primary" onClick={handleSaveEdit} isLoading={isSaving}>
              Save Changes
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-xs">
          {validationError && (
            <div className="p-3 bg-red-950/60 border border-red-800/60 rounded text-red-200">
              {validationError}
            </div>
          )}

          <div>
            <label className="font-semibold text-slate-200 block mb-1">Observation Threshold</label>
            <input
              type="number"
              min="1"
              value={thresholdInput}
              onChange={(e) => setThresholdInput(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Minimum count of observations or distinct ports required to trigger an alert.
            </p>
          </div>

          <div>
            <label className="font-semibold text-slate-200 block mb-1">
              Window Duration (seconds)
            </label>
            <input
              type="number"
              min="1"
              value={windowInput}
              onChange={(e) => setWindowInput(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Rolling evaluation window duration in seconds.
            </p>
          </div>

          <div>
            <label className="font-semibold text-slate-200 block mb-1">
              Alert Cooldown (seconds)
            </label>
            <input
              type="number"
              min="0"
              value={cooldownInput}
              onChange={(e) => setCooldownInput(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Quiet period between repetitive alerts for the same fingerprint (0 for none).
            </p>
          </div>

          <div>
            <label className="font-semibold text-slate-200 block mb-1">Max Evidence Records</label>
            <input
              type="number"
              min="1"
              max="100"
              value={maxEvidenceInput}
              onChange={(e) => setMaxEvidenceInput(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Maximum event IDs bound to generated alerts.
            </p>
          </div>

          <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
            <input
              type="checkbox"
              id="rule-enabled-chk"
              checked={enabledInput}
              onChange={(e) => setEnabledInput(e.target.checked)}
              className="rounded bg-slate-950 border-slate-800 text-cyan-600 focus:ring-cyan-500"
            />
            <label htmlFor="rule-enabled-chk" className="font-semibold text-slate-200 cursor-pointer">
              Rule Enabled
            </label>
          </div>
        </div>
      </Modal>

      {/* Disabling Warning Modal */}
      <Modal
        isOpen={ruleToToggle !== null}
        onClose={() => setRuleToToggle(null)}
        title="Confirm Disabling Detection Rule"
        description={`Rule ID: ${ruleToToggle?.rule_id}`}
        footer={
          <>
            <Button size="sm" variant="secondary" onClick={() => setRuleToToggle(null)} disabled={isSaving}>
              Cancel
            </Button>
            <Button size="sm" variant="danger" onClick={handleConfirmToggleDisable} isLoading={isSaving}>
              Disable Rule
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-xs">
          <div className="p-3 bg-red-950/40 border border-red-800/60 rounded text-red-200 flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <p>
              Disabling this detection rule will immediately stop threat correlation for{' '}
              <strong className="text-white">{ruleToToggle?.name}</strong>. Ongoing or future malicious
              activity matching this profile will not generate alerts.
            </p>
          </div>
          <p className="text-slate-300">
            Are you sure you want to disable rule <span className="font-mono text-cyan-400">{ruleToToggle?.rule_id}</span>?
          </p>
        </div>
      </Modal>
    </div>
  );
};
