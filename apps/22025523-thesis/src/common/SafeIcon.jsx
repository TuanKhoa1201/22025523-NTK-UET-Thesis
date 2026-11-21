import React from 'react';
import * as FiIcons from 'react-icons/fi';
import { FiAlertTriangle } from 'react-icons/fi';

const ICON_ALIASES = Object.freeze({
  Bug: 'AlertOctagon',
  Code2: 'Code',
  FileArchive: 'Archive',
  FileCode: 'Code',
  FolderGit2: 'Folder',
  KeyRound: 'Key',
  Lightbulb: 'Zap',
  PanelLeftClose: 'Sidebar',
  PanelLeftOpen: 'Sidebar',
  Scan: 'Crosshair',
  ScanSearch: 'Search',
  Settings2: 'Settings',
  ShieldAlert: 'AlertOctagon',
  ShieldCheck: 'CheckCircle',
  TriangleAlert: 'AlertTriangle',
});

export function resolveIconName(name) {
  if (!name || typeof name !== 'string') return null;
  if (FiIcons[`Fi${name}`]) return `Fi${name}`;
  const alias = ICON_ALIASES[name];
  if (alias && FiIcons[`Fi${alias}`]) return `Fi${alias}`;
  return null;
}

const SafeIcon = ({ icon, name, ...props }) => {
  let IconComponent = icon || null;
  if (!IconComponent && name) {
    const resolved = resolveIconName(name);
    IconComponent = resolved ? FiIcons[resolved] : null;
  }

  return IconComponent
    ? React.createElement(IconComponent, {'aria-hidden': true, ...props})
    : <FiAlertTriangle aria-hidden="true" {...props} />;
};

export default SafeIcon;
