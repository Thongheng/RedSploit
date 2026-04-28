# Requirements Document: TUI Redesign

## Introduction

This document specifies the requirements for the RedSploit Terminal User Interface (TUI) redesign. The redesign modernizes workflow execution output with improved visual hierarchy, cleaner progress indicators, better color schemes, and enhanced readability. The system transforms the current implementation into a cohesive, modern terminal experience that makes workflow execution easier to follow and understand.

## Glossary

- **TUI**: Terminal User Interface - the visual display system in the terminal
- **Workflow_Display**: Component responsible for rendering workflow-level UI elements (header, progress, summary)
- **Step_Display**: Component responsible for rendering individual step UI elements (cards, output, completion)
- **Display_Theme**: Configuration object defining colors, icons, and layout constants
- **Progress_Reporter**: Orchestrator that coordinates TUI rendering during workflow execution
- **Rich_Formatter**: Output formatter using the Rich library for terminal styling
- **Collapsible_Output**: Output manager that handles truncation and expansion of step output
- **Step_Card**: Visual card component displaying step start information
- **Progress_Bar**: Visual bar component showing workflow completion percentage
- **Summary_Panel**: Visual panel component displaying workflow completion statistics
- **Status_Icon**: Unicode symbol representing step execution status
- **Truncation_Notice**: Visual indicator that output has been truncated with expansion instructions

## Requirements

### Requirement 1: Workflow Header Display

**User Story:** As a user, I want to see clear workflow execution information at the start, so that I understand what workflow is running and its configuration.

#### Acceptance Criteria

1. WHEN a workflow execution starts, THE Workflow_Display SHALL render a header panel containing workflow metadata
2. THE header panel SHALL include the workflow name, target name, execution mode, and profile name
3. THE header panel SHALL use the Display_Theme primary color for visual emphasis
4. THE header panel SHALL include appropriate padding as defined in Display_Theme configuration

### Requirement 2: Progress Bar Display

**User Story:** As a user, I want to see overall workflow progress, so that I can understand how much of the workflow has completed.

#### Acceptance Criteria

1. WHEN a workflow is executing, THE Workflow_Display SHALL render a progress bar showing completion percentage
2. THE progress bar SHALL display the ratio of completed steps to total steps
3. THE progress bar SHALL use Display_Theme progress characters (complete and incomplete)
4. THE progress bar SHALL calculate percentage as (completed_steps / total_steps) * 100
5. WHEN all steps are complete, THE progress bar SHALL show 100% completion
6. THE progress bar SHALL count steps with status "complete", "failed", or "skipped" as completed
7. THE progress bar width SHALL be configurable through Display_Theme

### Requirement 3: Step Card Rendering

**User Story:** As a user, I want to see clear step start information, so that I know which tool is executing and its configuration.

#### Acceptance Criteria

1. WHEN a step starts execution, THE Step_Display SHALL render a step card with step metadata
2. THE step card SHALL include the step ID and tool name
3. THE step card SHALL include a running status icon from Display_Theme
4. WHEN step configuration is available, THE step card SHALL display configuration key-value pairs
5. THE step card SHALL use Rich panel formatting with info border style
6. THE step card SHALL apply Display_Theme padding configuration

### Requirement 4: Step Output Streaming

**User Story:** As a user, I want to see step output in real-time, so that I can monitor tool execution progress.

#### Acceptance Criteria

1. WHEN a step produces output, THE Step_Display SHALL render output lines to the terminal
2. THE Step_Display SHALL apply appropriate styling based on log level (info, warning, error)
3. THE Step_Display SHALL stream output without blocking step execution
4. THE output SHALL be buffered by Collapsible_Output for later retrieval

### Requirement 5: Output Truncation

**User Story:** As a user, I want verbose output to be truncated automatically, so that my terminal doesn't become cluttered with excessive output.

#### Acceptance Criteria

1. WHEN step output exceeds the maximum preview line limit, THE Collapsible_Output SHALL truncate displayed output
2. THE Collapsible_Output SHALL buffer all output lines regardless of truncation
3. WHEN output is truncated, THE Step_Display SHALL render a truncation notice
4. THE truncation notice SHALL display the number of hidden lines
5. THE truncation notice SHALL include instructions for viewing full output (keyboard shortcut)
6. THE maximum preview line limit SHALL be configurable (default 10,000 lines)

### Requirement 6: Step Completion Display

**User Story:** As a user, I want to see clear step completion status, so that I know whether steps succeeded or failed.

#### Acceptance Criteria

1. WHEN a step completes successfully, THE Step_Display SHALL render a completion footer with statistics
2. THE completion footer SHALL include step duration formatted as MM:SS
3. THE completion footer SHALL include output line count
4. THE completion footer SHALL use a success status icon from Display_Theme
5. WHEN a step fails, THE Step_Display SHALL render error details instead of a standard footer
6. WHEN a step is skipped, THE Step_Display SHALL render a footer with dim styling

### Requirement 7: Error Detail Display

**User Story:** As a user, I want to see detailed error information when steps fail, so that I can understand what went wrong and how to fix it.

#### Acceptance Criteria

1. WHEN a step fails, THE Step_Display SHALL render an error details panel
2. THE error details panel SHALL include the error summary from the step
3. THE error details panel SHALL include step duration
4. THE error details panel SHALL use Display_Theme error color for visual emphasis
5. THE error details panel SHALL use a failed status icon from Display_Theme

### Requirement 8: Workflow Summary Display

**User Story:** As a user, I want to see workflow completion statistics, so that I understand the overall execution outcome.

#### Acceptance Criteria

1. WHEN a workflow completes, THE Workflow_Display SHALL render a summary panel
2. THE summary panel SHALL include workflow completion status (complete or failed)
3. THE summary panel SHALL include counts of completed, failed, and skipped steps
4. THE summary panel SHALL include total workflow duration formatted as MM:SS
5. THE summary panel SHALL use success color when workflow completes successfully
6. THE summary panel SHALL use error color when workflow fails
7. THE sum of step counts (complete + failed + skipped) SHALL equal total step count

### Requirement 9: Theme Configuration

**User Story:** As a developer, I want to customize TUI appearance through theme configuration, so that I can match organizational branding or personal preferences.

#### Acceptance Criteria

1. THE Display_Theme SHALL define color values for primary, success, warning, error, info, and dim states
2. THE Display_Theme SHALL define status icons for running, complete, failed, skipped, and pending states
3. THE Display_Theme SHALL define layout configuration including panel padding, separator character, separator width, and indent size
4. THE Display_Theme SHALL define progress bar configuration including width, complete character, and incomplete character
5. THE Display_Theme SHALL provide methods to retrieve status icons and colors by status value
6. WHEN theme configuration contains invalid values, THE system SHALL use default values for invalid fields

### Requirement 10: Visual Consistency

**User Story:** As a user, I want consistent visual styling across all TUI components, so that the interface feels cohesive and professional.

#### Acceptance Criteria

1. THE Workflow_Display SHALL use Display_Theme colors and icons consistently
2. THE Step_Display SHALL use Display_Theme colors and icons consistently
3. THE Progress_Reporter SHALL apply Display_Theme configuration to all rendered components
4. WHEN rendering any TUI component, THE system SHALL maintain proper indentation using Display_Theme indent_size
5. WHEN rendering any TUI component, THE system SHALL include visual separators between sections using Display_Theme separator configuration

### Requirement 11: Fallback Rendering

**User Story:** As a user on a limited terminal, I want the TUI to work even when Rich library features are unavailable, so that I can still use the tool.

#### Acceptance Criteria

1. WHEN Rich library fails to initialize, THE system SHALL fall back to plain text output
2. THE plain text fallback SHALL maintain information hierarchy using indentation
3. THE plain text fallback SHALL use simple separators instead of Rich panels
4. THE plain text fallback SHALL disable advanced formatting features (colors, panels)
5. THE system SHALL continue workflow execution when fallback mode is active

### Requirement 12: Output Expansion

**User Story:** As a user, I want to view full step output when needed, so that I can investigate issues or review complete tool output.

#### Acceptance Criteria

1. WHEN output is truncated, THE system SHALL provide a keyboard shortcut to view full output
2. THE keyboard shortcut SHALL be Ctrl+O
3. WHEN the keyboard shortcut is triggered, THE system SHALL display full output in a pager
4. THE pager SHALL allow scrolling through complete output
5. THE full output SHALL include all buffered lines regardless of truncation

### Requirement 13: Progress Accuracy

**User Story:** As a user, I want accurate progress information, so that I can trust the displayed completion percentage.

#### Acceptance Criteria

1. THE progress bar percentage SHALL always be between 0 and 100 inclusive
2. THE completed step count SHALL never exceed total step count
3. WHEN progress bar shows 100%, THE system SHALL ensure all steps have terminal status (complete, failed, or skipped)
4. THE progress bar SHALL update after each step completes

### Requirement 14: Display State Consistency

**User Story:** As a developer, I want display state to remain consistent with execution state, so that the UI accurately reflects reality.

#### Acceptance Criteria

1. WHEN tracking step display state, THE system SHALL ensure display status matches step execution status
2. THE displayed output line count SHALL never exceed total output lines received
3. WHEN output is marked as truncated, THE total output lines SHALL exceed the maximum preview line limit
4. THE system SHALL maintain display state for each step during execution

### Requirement 15: Output Safety

**User Story:** As a user, I want all output to be preserved safely, so that no data is lost even when truncation occurs.

#### Acceptance Criteria

1. THE Collapsible_Output SHALL buffer all received output lines
2. THE Collapsible_Output line count SHALL equal actual lines received
3. THE Collapsible_Output full output retrieval SHALL contain all buffered lines
4. WHEN output is truncated for display, THE system SHALL preserve all lines in the buffer

### Requirement 16: Terminal Compatibility

**User Story:** As a user on different operating systems, I want the TUI to work correctly on my platform, so that I have a consistent experience.

#### Acceptance Criteria

1. THE system SHALL support ANSI color codes on Unix-like systems
2. THE system SHALL support ANSI color codes on Windows when colorama is available
3. THE system SHALL detect terminal capabilities and adjust rendering accordingly
4. WHEN terminal doesn't support ANSI colors, THE system SHALL use plain text fallback

### Requirement 17: Performance Efficiency

**User Story:** As a user running long workflows, I want the TUI to remain responsive, so that output display doesn't slow down execution.

#### Acceptance Criteria

1. THE system SHALL stream output to terminal without blocking step execution
2. THE system SHALL limit buffered output per step to prevent excessive memory usage
3. THE default buffer limit SHALL be 10,000 lines per step
4. THE buffer limit SHALL be configurable
5. THE system SHALL use efficient string operations for output processing

### Requirement 18: Security and Sanitization

**User Story:** As a user, I want tool output to be safely displayed, so that malicious output cannot compromise my terminal.

#### Acceptance Criteria

1. THE system SHALL escape ANSI control sequences in tool output
2. THE system SHALL prevent terminal injection attacks through output sanitization
3. THE system SHALL validate all user-provided theme configuration values
4. THE system SHALL sanitize file paths in error messages
5. THE system SHALL avoid displaying sensitive data (API keys, passwords) in output

