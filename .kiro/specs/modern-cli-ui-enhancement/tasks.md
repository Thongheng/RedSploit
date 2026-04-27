# Implementation Plan: Modern CLI UI Enhancement

## Overview

This implementation plan breaks down the integration of the Rich library into the RedSploit CLI following a 5-phase approach. Each phase builds incrementally on the previous one, starting with core components and progressing through basic integration, structured data display, advanced features, and final polish. The implementation maintains full backward compatibility with the existing prompt_toolkit REPL while adding sophisticated visual components.

## Tasks

- [x] 1. Phase 1: Foundation - Create core Rich components
  - [x] 1.1 Create rich_theme.py with theme definitions and console factory
    - Create `redsploit/core/rich_theme.py`
    - Define RichTheme class with terracotta accent color (#e05a2f)
    - Implement color constants (SUCCESS, WARNING, ERROR, INFO, DIM)
    - Implement `get_theme()` method returning Rich Theme object
    - Implement `get_console()` method creating Console with theme
    - _Requirements: 1.1, 1.2, 10.1, 10.2_

  - [x] 1.2 Create rich_output.py with RichOutputFormatter and console singleton
    - Create `redsploit/core/rich_output.py`
    - Implement console singleton pattern with `get_console()` and `reset_console()`
    - Implement RichOutputFormatter class with message methods (info, success, warn, error, run)
    - Implement panel rendering method with terracotta border styling
    - Implement table rendering method with column alignment
    - Implement syntax highlighting method
    - Implement help_panel method for command help display
    - Implement error_panel method for exception display
    - Add safe_render decorator for graceful fallback to plain text
    - _Requirements: 1.1, 1.3, 2.1, 2.2, 2.3, 2.4, 3.1, 3.3, 4.1, 4.4, 7.1, 11.4_

  - [x] 1.3 Update colors.py to use Rich-based log functions
    - Modify `redsploit/core/colors.py`
    - Replace log_info() implementation to call RichOutputFormatter.info()
    - Replace log_success() implementation to call RichOutputFormatter.success()
    - Replace log_warn() implementation to call RichOutputFormatter.warn()
    - Replace log_error() implementation to call RichOutputFormatter.error()
    - Replace log_run() implementation to call RichOutputFormatter.run()
    - Maintain backward compatible function signatures
    - _Requirements: 2.5, 11.1, 11.2_

  - [x] 1.4 Add Rich dependency to pyproject.toml
    - Add `rich = "^13.7.0"` to dependencies in pyproject.toml
    - _Requirements: 1.1_

- [x] 2. Phase 2: Basic Integration - Update messages and add panels
  - [x] 2.1 Add panel rendering to module entry points
    - Modify `redsploit/core/base_shell.py` ModuleShell.preloop() method
    - Add Rich Panel display showing module name and description
    - Display current session context (target, domain, user) in panel
    - Use terracotta border styling for consistency
    - _Requirements: 5.1, 5.2, 5.5_

  - [x] 2.2 Update help display to use Rich panels and syntax highlighting
    - Modify `redsploit/modules/base.py` print_tool_help() method
    - Wrap help content in Rich Panel with tool name as title
    - Organize help sections (description, usage, requirements, examples)
    - Apply syntax highlighting to code examples using Rich Syntax component
    - Use terracotta accent color for borders and tool names
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 2.3 Update BaseShell.do_help() to use Rich formatting
    - Modify `redsploit/core/base_shell.py` do_help() method
    - Keep existing categorized command display structure
    - Enhance visual presentation with Rich styling for headers and categories
    - Maintain existing box drawing for module commands
    - _Requirements: 3.1, 3.4_

- [x] 3. Checkpoint - Verify basic Rich integration
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Phase 3: Structured Data - Convert displays to Rich tables
  - [x] 4.1 Update Session.show_options() to use Rich tables
    - Modify `redsploit/core/session.py` show_options() method
    - For brief mode: Keep existing simple display format
    - For full mode: Replace manual table formatting with Rich Table
    - Add columns: Variable, Value, Required, Description
    - Apply terracotta styling to headers
    - Right-align numeric values, left-align text
    - Show "(not set)" in dim style for empty required fields
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

  - [x] 4.2 Update loot display to use Rich tables
    - Modify `redsploit/core/loot.py` list_loot() method
    - Replace manual formatting with Rich Table
    - Add columns: ID, Type, Service, Content, Target, Timestamp
    - Apply terracotta styling to headers
    - Truncate long content values with ellipsis
    - Show styled message when loot list is empty
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

  - [x] 4.3 Update workspace list to use Rich tables
    - Modify `redsploit/core/session.py` list_workspaces() method
    - Replace box drawing with Rich Table
    - Add columns: Status (●/○), Workspace Name
    - Highlight current workspace with green indicator and bold text
    - Apply terracotta styling to table borders
    - Show styled message when no workspaces exist
    - _Requirements: 4.1, 4.2, 4.3, 4.5_

  - [x] 4.4 Update tool configuration display to use Rich tables
    - Modify `redsploit/core/session.py` show_configs() method
    - Replace manual formatting with Rich Table
    - Add columns: Tool, Config Key, Value, Flags
    - Apply terracotta styling to headers
    - Show styled message when no configurations are active
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 5. Phase 4: Advanced Features - Add syntax highlighting and error panels
  - [x] 5.1 Add Rich error panels for exception handling
    - Identify exception handling locations in base_shell.py and modules
    - Wrap exception displays in Rich Panel with red accent
    - Include error type, message, and traceback (when available)
    - Add suggestions or next steps when applicable
    - Distinguish user errors from system errors with different styling
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 5.2 Add Rich formatting to command suggestions
    - Modify `redsploit/core/shell.py` default() method
    - Display "Unknown command" message using Rich styling
    - Format suggestion list with Rich markup
    - Highlight matching portions of suggested commands
    - Show module context for each suggestion
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

  - [x] 5.3 Add Rich formatting to workflow output
    - Modify `redsploit/workflow/execution.py` or relevant workflow display methods
    - Add workflow start panel showing workflow name and target
    - Display workflow step progress with styled status indicators
    - Add workflow completion summary panel with execution statistics
    - Format workflow findings table with severity colors (critical=red, high=red, medium=yellow, info=dim)
    - Use consistent terracotta panel styling
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 6. Checkpoint - Verify advanced features integration
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Phase 5: Polish and Optimization
  - [x] 7.1 Add configuration options for Rich UI
    - Add UI configuration section to config.yaml
    - Add options: rich_enabled, theme, force_color, max_table_rows, panel_padding, show_icons
    - Update RichOutputFormatter to respect configuration settings
    - Add ability to disable Rich globally via config
    - _Requirements: 11.4, 12.3_

  - [x] 7.2 Performance optimization and testing
    - Profile Rich rendering performance for typical operations
    - Ensure rendering time < 100ms for messages, panels, and tables with < 100 rows
    - Implement table pagination or truncation for large datasets (> max_table_rows)
    - Verify console singleton reuse (no repeated instance creation)
    - Test REPL responsiveness during Rich output rendering
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

  - [x] 7.3 Terminal compatibility testing
    - Test in standard terminal emulators (iTerm2, Terminal.app, GNOME Terminal, Windows Terminal)
    - Test over SSH connections
    - Verify graceful fallback in limited terminals
    - Test with different terminal widths and color support levels
    - Ensure fallback to plain text when Rich rendering fails
    - _Requirements: 11.4, 12.1_

  - [x] 7.4 Visual refinement and spacing adjustments
    - Review all Rich output for consistent spacing and alignment
    - Adjust panel padding for optimal readability
    - Ensure terracotta accent color appears consistently across all components
    - Verify table column widths are appropriate for typical content
    - Fine-tune syntax highlighting theme for readability
    - _Requirements: 10.3, 10.4_

  - [ ]* 7.5 Write unit tests for Rich components
    - Test RichTheme.get_theme() returns correct style definitions
    - Test RichTheme.get_console() creates Console with theme applied
    - Test console singleton pattern (get_console returns same instance)
    - Test RichOutputFormatter message methods (info, success, warn, error, run)
    - Test RichOutputFormatter panel rendering
    - Test RichOutputFormatter table rendering with various data structures
    - Test RichOutputFormatter syntax highlighting
    - Test backward compatible log functions produce output
    - Test graceful fallback when Rich rendering fails
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 2.4, 11.4_

  - [ ]* 7.6 Write integration tests for REPL interaction
    - Test Rich output doesn't interfere with prompt_toolkit input
    - Test command history works with Rich output
    - Test auto-completion works with Rich output
    - Test output appears between prompts correctly
    - _Requirements: 1.4, 1.5, 11.2, 12.2_

- [x] 8. Final checkpoint - Complete implementation verification
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional testing tasks and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- The implementation follows a layered approach: foundation → basic integration → structured data → advanced features → polish
- Backward compatibility is maintained throughout - existing code continues to work unchanged
- Rich components wrap existing output mechanisms without disrupting core REPL functionality
- The terracotta accent color (#e05a2f) is used consistently across all Rich components
- Graceful fallback to plain text is implemented for terminal compatibility
