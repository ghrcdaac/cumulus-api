# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and includes an additional section for migration notes.

- *Migration Notes* - Notes for end users to migrate to the version.
- *Added* - New features.
- *Changed* - Changes in existing functionality.
- *Deprecated* - Soon-to-be removed features.
- *Removed* - Now removed features.
- *Fixed* - Any bug fixes.
- *Security* - Vulnerabilities fixes and changes.

## [1.2.0]

Added launchpad integration and missing Cumulus API endpoints.

### Migration Notes

- The update methods have been revised to extract the name/versions from 
the payload data to reduce redundancies.
- The get_token() method input has changed and should be replaced with
.TOKEN class variable assignment instead.

### Added

- Launchpad integration for authentication bearer token added.
- Many additional methods added to accomodate missing Cumulus API endpoints.

### Changed

- The following methods were updated to extract previously required parameters
from a required payload:
  - update_collection()
  - update_provider()
  - update_rule()

### Removed

- The get_token() method should no longer be used when trying to return the token
value and should instead be replaced with the .TOKEN class variable
- The get_stats_histogram() method was removed because this endpoint is no longer
available from Cumulus.

## [1.1.3]

Update run rules method

### Added

- Updated run rules method for expected payload

## [1.1.0]

Run rules method added

### Added

- Added initial run rules method 

## [0.1.0]

Initial deployment containing baseline Cumulus endpoints

### Added

- Added standard Apache license
- Added README instructions
- Added baseline Cumulus API endpoints
- Added baseline Cumulus API endpoint examples
