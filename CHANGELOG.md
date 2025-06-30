# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-19

### Added
- **Initial release** of syft-perm
- **File permission management** for SyftBox files
- **Core functions**:
  - `set_file_permissions()` - Set read/write/admin permissions for files
  - `get_file_permissions()` - Read existing permissions from syft.pub.yaml
  - `remove_file_permissions()` - Remove permissions for files
- **SyftBox integration** with syft-core optional dependency
- **Syft:// URL support** - Works with both local paths and syft:// URLs
- **YAML-based permissions** - Creates and manages syft.pub.yaml files
- **Flexible user specification** - Supports individual users and "public" access
- **Pattern-based rules** - Uses file patterns for permission matching

### Features
- Minimal dependencies (only PyYAML required)
- Optional SyftBox integration for full functionality
- Clean API with three main functions
- Automatic syft.pub.yaml file management
- Support for read, write, and admin permission levels
- Public access support with "*" wildcard 