/** Information about the source file for breakpoints. */
export interface Source {
  /** The short name of the source (e.g., filename). */
  name?: string
  /** The full path to the source file. */
  path?: string
  /** An optional reference to a source stored in the debugger. */
  sourceReference?: number
}

export interface SourceBreakpoint {
  /**
   * The source line of the breakpoint or logpoint.
   */
  line: number

  /**
   * Start position within source line of the breakpoint or logpoint. It is
   * measured in UTF-16 code units and the client capability `columnsStartAt1`
   * determines whether it is 0- or 1-based.
   */
  column?: number

  /**
   * The expression for conditional breakpoints.
   * It is only honored by a debug adapter if the corresponding capability
   * `supportsConditionalBreakpoints` is true.
   */
  condition?: string

  /**
   * The expression that controls how many hits of the breakpoint are ignored.
   * The debug adapter is expected to interpret the expression as needed.
   * The attribute is only honored by a debug adapter if the corresponding
   * capability `supportsHitConditionalBreakpoints` is true.
   * If both this property and `condition` are specified, `hitCondition` should
   * be evaluated only if the `condition` is met, and the debug adapter should
   * stop only if both conditions are met.
   */
  hitCondition?: string

  /**
   * If this attribute exists and is non-empty, the debug adapter must not
   * 'break' (stop)
   * but log the message instead. Expressions within `{}` are interpolated.
   * The attribute is only honored by a debug adapter if the corresponding
   * capability `supportsLogPoints` is true.
   * If either `hitCondition` or `condition` is specified, then the message
   * should only be logged if those conditions are met.
   */
  logMessage?: string

  /**
   * The mode of this breakpoint. If defined, this must be one of the
   * `breakpointModes` the debug adapter advertised in its `Capabilities`.
   */
  mode?: string
}

export interface SetBreakpointsArguments {
  /**
   * The source location of the breakpoints; either `source.path` or
   * `source.sourceReference` must be specified.
   */
  source: Source
  /**
   * The code locations of the breakpoints.
   */
  breakpoints?: SourceBreakpoint[]
  /**
   * Deprecated: The code locations of the breakpoints.
   */
  lines?: number[]
  /**
   * A value of true indicates that the underlying source has been modified
   * which results in new breakpoint locations.
   */
  sourceModified?: boolean
}

export interface SetBreakpointsExtensionArguments {
  /** A string identifying the source file. */
  source: string
  /** An array of string identifiers for breakpoints. */
  identifiers: string[]
}
