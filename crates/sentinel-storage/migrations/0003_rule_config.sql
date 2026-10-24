-- Migration 0003: Add config_json to detection_rules for rule parameter persistence
ALTER TABLE detection_rules ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}';
