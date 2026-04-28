# Implementation Plan: TUI Redesign

## Overview

This implementation plan transforms the RedSploit workflow execution display into a modern, cohesive terminal experience. The approach follows a layered strategy: first establishing the foundational theme and display components, then integrating them with the existing workflow execution system, and finally adding advanced features like output truncation and error handling. Each task builds incrementally, ensuring that core functionality is validated early through code.

## Tasks

- [x] 1. Create DisplayTheme configuration system
  - Create `redsploit/workflow/display_theme.py` with DisplayTheme dataclass
  - Implement color palette (primary, success, warning, error, info, dim)
  - Implement status icons (running, complete, failed, skipped, pending)
  - Implement layout configuration (panel_padding, separator_char, separator_width, indent_size)
  - Implement progress bar configuration (width, complete_char, incomplete_char)
  - Add `get_status_icon()` and `get_status_color()` methods
  - Add validation for color values and layout dimensions
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

- [ ]* 1.1 Write unit tests for DisplayTheme
  - Test theme initialization with valid and invalid configurations
  - Test status icon and color retrieval for all valid statuses
  - Test validation of color values and layout dimensions
  - Test default value fallback for invalid fields
  - _Requirements: 9.6_

- [x] 2. Create WorkflowDisplay component
  - Create `redsploit/workflow/workflow_display.py` with WorkflowDisplay class
  - Implement `__init__()` accepting RichOutputFormatter and DisplayTheme
  - Implement `render_header()` to display workflow metadata panel
  - Implement `render_progress_bar()` to show completion percentage
  - Implement `render_summary()` to display final statistics
  - Use theme colors and layout configuration consistently
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_

- [ ]* 2.1 Write property test for progress bar accuracy
  - **Property 1: Progress Bar Accuracy**
  - **Validates: Requirements 2.2, 2.4, 13.1, 13.2, 13.3**
  - Test that progress percentage is always between 0 and 100
  - Test that completed count never exceeds total count
  - Test that 100% completion implies all steps have terminal status
  - Use Hypothesis to generate various step status combinations

- [ ]* 2.2 Write property test for progress bar rendering
  - **Property 6: Progress Bar Rendering**
  - **Validates: Requirements 2.2, 2.3, 2.6, 2.7**
  - Test that progress bar displays correct ratio of completed to total steps
  - Test that progress bar uses theme-configured characters
  - Test that progress bar width matches theme configuration
  - Use Hypothesis to generate various completion states

- [ ]* 2.3 Write unit tests for WorkflowDisplay
  - Test header rendering with workflow metadata
  - Test progress bar rendering at 0%, 50%, and 100% completion
  - Test summary rendering for successful and failed workflows
  - Test theme color application in all components
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 8.1, 8.2, 8.3_

- [x] 3. Create StepDisplay component
  - Create `redsploit/workflow/step_display.py` with StepDisplay class
  - Implement `__init__()` accepting RichOutputFormatter and DisplayTheme
  - Implement `render_step_header()` to display step card with metadata
  - Implement `render_step_footer()` to show completion badge with timing
  - Implement `render_output_line()` to display output with log level styling
  - Implement `render_error_details()` to show detailed error information
  - Implement `render_truncation_notice()` to display hidden line count
  - Use theme colors, icons, and layout configuration consistently
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.1, 4.2, 4.3, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 7.1, 7.2, 7.3, 7.4, 7.5, 5.3, 5.4, 5.5_

- [ ]* 3.1 Write property test for step card content
  - **Property 7: Step Card Content**
  - **Validates: Requirements 3.2, 3.3, 3.4**
  - Test that step card includes step ID and tool name
  - Test that step card displays running status icon from theme
  - Test that step card includes configuration key-value pairs when available
  - Use Hypothesis to generate various step configurations

- [ ]* 3.2 Write property test for output line styling
  - **Property 8: Output Line Styling**
  - **Validates: Requirements 4.2**
  - Test that output lines apply appropriate styling based on log level
  - Test styling for info, warning, and error levels
  - Use Hypothesis to generate various log levels and content

- [ ]* 3.3 Write unit tests for StepDisplay
  - Test step header rendering with tool name and configuration
  - Test step footer rendering with timing and output count
  - Test output line rendering with different log levels
  - Test error details rendering with error summary
  - Test truncation notice rendering with hidden line count
  - _Requirements: 3.1, 3.2, 4.1, 6.1, 7.1, 5.3_

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Enhance CollapsibleOutput for truncation
  - Modify `redsploit/workflow/collapsible_output.py`
  - Add `max_preview_lines` parameter to CollapsibleOutput (default 10,000)
  - Add `is_truncated()` method to check if output exceeds limit
  - Add `get_hidden_line_count()` method to calculate hidden lines
  - Ensure all output lines are buffered regardless of truncation
  - Ensure `get_line_count()` returns actual lines received
  - Ensure `get_full_output()` returns all buffered lines
  - _Requirements: 5.1, 5.2, 5.6, 15.1, 15.2, 15.3, 15.4_

- [ ]* 5.1 Write property test for output truncation safety
  - **Property 4: Output Truncation Safety**
  - **Validates: Requirements 5.2, 15.1, 15.2, 15.3, 15.4**
  - Test that all received lines are buffered regardless of truncation
  - Test that line count equals actual lines received
  - Test that full output retrieval contains all buffered lines
  - Test that truncation for display preserves all lines in buffer
  - Use Hypothesis to generate various line counts (0 to 50,000)

- [ ]* 5.2 Write property test for truncation behavior
  - **Property 9: Truncation Behavior**
  - **Validates: Requirements 5.1, 5.3, 5.4**
  - Test that output exceeding max preview lines is truncated for display
  - Test that truncation notice is rendered when truncated
  - Test that notice displays correct number of hidden lines
  - Use Hypothesis to generate various line counts around threshold

- [ ]* 5.3 Write unit tests for CollapsibleOutput truncation
  - Test truncation at various line thresholds (100, 1000, 10000)
  - Test `is_truncated()` returns correct value
  - Test `get_hidden_line_count()` calculates correctly
  - Test buffer integrity with large outputs
  - _Requirements: 5.1, 5.2, 5.6_

- [x] 6. Create StepDisplayState tracking model
  - Create `redsploit/workflow/step_display_state.py` with StepDisplayState dataclass
  - Add fields: step_id, start_time, output_lines_shown, output_lines_total, is_truncated, last_update, status
  - Add validation: step_id non-empty, output_lines_shown <= output_lines_total, valid status values
  - _Requirements: 14.1, 14.2, 14.3, 14.4_

- [ ]* 6.1 Write property test for step display consistency
  - **Property 2: Step Display Consistency**
  - **Validates: Requirements 14.1, 14.2, 14.3**
  - Test that display status matches step execution status
  - Test that displayed output line count never exceeds total output lines
  - Test that truncation flag implies output exceeds max line limit
  - Use Hypothesis to generate various display states

- [ ]* 6.2 Write unit tests for StepDisplayState
  - Test initialization with valid and invalid values
  - Test validation rules for output line counts
  - Test validation rules for status values
  - _Requirements: 14.1, 14.2, 14.3_

- [x] 7. Create enhanced ProgressReporter
  - Create `redsploit/workflow/progress_reporter.py` with ProgressReporter class
  - Implement `__init__()` accepting optional DisplayTheme
  - Implement `run_header()` to display workflow start with header and progress bar
  - Implement `step_started()` to display step start with card layout
  - Implement `step_completed()` to display step completion with badge
  - Implement `step_failed()` to display step failure with error details
  - Implement `step_skipped()` to display skipped step with dim styling
  - Implement `run_footer()` to display workflow completion summary
  - Implement `update_progress()` to refresh progress bar
  - Track StepDisplayState for each step during execution
  - Coordinate with CliLogPublisher for output streaming
  - _Requirements: 1.1, 2.1, 3.1, 4.1, 6.1, 6.5, 6.6, 7.1, 8.1, 10.1, 10.2, 10.3, 10.4, 10.5_

- [ ]* 7.1 Write property test for visual hierarchy preservation
  - **Property 3: Visual Hierarchy Preservation**
  - **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**
  - Test that components use theme colors consistently
  - Test that components maintain proper indentation per theme
  - Test that components include visual separators between sections
  - Test that components apply status-appropriate styling
  - Use Hypothesis to generate various component rendering scenarios

- [ ]* 7.2 Write unit tests for ProgressReporter
  - Test workflow header rendering
  - Test step lifecycle rendering (started, completed, failed, skipped)
  - Test workflow summary rendering
  - Test progress bar updates after each step
  - Test StepDisplayState tracking
  - _Requirements: 1.1, 2.1, 3.1, 6.1, 7.1, 8.1_

- [x] 8. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Integrate ProgressReporter with WorkflowManager
  - Modify `redsploit/workflow/manager.py` to use new ProgressReporter
  - Replace existing progress reporting calls with ProgressReporter methods
  - Pass CliLogPublisher to ProgressReporter for output coordination
  - Ensure workflow execution flow remains unchanged
  - Test integration with real workflow YAML files
  - _Requirements: 1.1, 2.1, 3.1, 4.1, 6.1, 7.1, 8.1_

- [ ]* 9.1 Write integration tests for workflow execution
  - Test full workflow execution with multiple steps
  - Test workflow with failed steps and error details
  - Test workflow with mixed step statuses (complete, failed, skipped)
  - Test progress bar accuracy throughout execution
  - _Requirements: 1.1, 2.1, 3.1, 6.1, 7.1, 8.1_

- [x] 10. Implement output streaming with truncation
  - Modify ProgressReporter to integrate with CollapsibleOutput
  - In `step_started()`, create CollapsibleOutput for step with max_preview_lines
  - During step execution, stream output through CollapsibleOutput
  - After step completes, check if output is truncated
  - If truncated, call StepDisplay.render_truncation_notice()
  - Ensure output streaming doesn't block step execution
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 5.1, 5.2, 5.3, 5.4, 5.5, 17.1, 17.2_

- [ ]* 10.1 Write property test for output buffer integrity
  - **Property 15: Output Buffer Integrity**
  - **Validates: Requirements 4.4, 5.2**
  - Test that any output line added to buffer is buffered and retrievable
  - Test that lines are retrievable regardless of display or truncation
  - Use Hypothesis to generate various output patterns

- [ ]* 10.2 Write integration tests for output truncation
  - Test workflow with output exceeding max preview lines
  - Test truncation notice rendering
  - Test full output retrieval after truncation
  - _Requirements: 5.1, 5.3, 5.4_

- [x] 11. Implement output expansion with keyboard shortcut
  - Add keyboard listener for Ctrl+O shortcut
  - When Ctrl+O is pressed, identify current step
  - Retrieve full output from CollapsibleOutput
  - Display full output in pager (using pydoc.pager)
  - Ensure keyboard listener runs in background thread
  - Handle Unix-only terminal control (termios, tty, select)
  - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

- [ ]* 11.1 Write unit tests for output expansion
  - Test keyboard shortcut detection (mock terminal input)
  - Test full output retrieval
  - Test pager invocation with full output
  - _Requirements: 12.1, 12.2, 12.3, 12.4_

- [x] 12. Implement fallback rendering for limited terminals
  - Add fallback detection in RichOutputFormatter initialization
  - When Rich fails to initialize, set fallback mode flag
  - In fallback mode, use plain text output with indentation
  - In fallback mode, use simple separators instead of Rich panels
  - In fallback mode, disable colors and advanced formatting
  - Ensure workflow execution continues in fallback mode
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 16.1, 16.2, 16.3, 16.4_

- [ ]* 12.1 Write unit tests for fallback rendering
  - Test fallback detection when Rich is unavailable
  - Test plain text output formatting
  - Test information hierarchy with indentation
  - Test workflow execution in fallback mode
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [x] 13. Implement output sanitization for security
  - Add output sanitization in StepDisplay.render_output_line()
  - Escape ANSI control sequences in tool output
  - Prevent terminal injection attacks through output
  - Validate theme configuration values on initialization
  - Sanitize file paths in error messages
  - Avoid displaying sensitive data patterns (API keys, passwords)
  - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5_

- [ ]* 13.1 Write property test for security sanitization
  - **Property 17: Security Sanitization**
  - **Validates: Requirements 18.1, 18.2**
  - Test that output containing ANSI control sequences is escaped
  - Test that potential injection attacks are sanitized
  - Use Hypothesis to generate various malicious output patterns

- [ ]* 13.2 Write unit tests for output sanitization
  - Test ANSI escape sequence sanitization
  - Test terminal injection prevention
  - Test theme configuration validation
  - Test file path sanitization
  - Test sensitive data pattern detection
  - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5_

- [x] 14. Add performance optimizations
  - Implement efficient string operations for output processing
  - Add buffer limit enforcement (default 10,000 lines per step)
  - Ensure buffer limit is configurable
  - Optimize progress bar rendering to avoid unnecessary re-renders
  - Add batch output line processing if needed for performance
  - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5_

- [ ]* 14.1 Write property test for configuration limits
  - **Property 16: Configuration Limits**
  - **Validates: Requirements 5.6, 17.4**
  - Test that system respects configured max preview lines
  - Test that system respects configured buffer limit
  - Test that limits are applied consistently
  - Use Hypothesis to generate various limit configurations

- [ ]* 14.2 Write performance tests
  - Test output streaming performance with large outputs (10,000+ lines)
  - Test progress bar rendering performance
  - Test memory usage with buffer limits
  - _Requirements: 17.1, 17.2, 17.3_

- [x] 15. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Integration and polish
  - Test complete workflow execution with all features enabled
  - Verify visual consistency across all components
  - Test error handling for all error scenarios
  - Verify theme customization works correctly
  - Test on different terminal types (Unix, Windows with colorama)
  - Update documentation with usage examples
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 16.1, 16.2, 16.3, 16.4_

- [ ]* 16.1 Write end-to-end integration tests
  - Test full workflow execution with real YAML files
  - Test workflow with concurrent step execution (if supported)
  - Test theme customization through configuration
  - Test terminal compatibility on different platforms
  - _Requirements: 10.1, 16.1, 16.2, 16.3, 16.4_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- Property tests validate universal correctness properties from the design
- Unit tests validate specific examples and edge cases
- Integration tests verify end-to-end functionality
- The implementation uses Python with Rich library for terminal formatting
- All display components use DisplayTheme for consistent visual language
- Output truncation preserves all data while keeping terminal clean
- Security sanitization prevents terminal injection attacks
- Fallback rendering ensures compatibility with limited terminals
