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

interface Thread {
  /**
   * Unique identifier for the thread.
   */
  id: number

  /**
   * The name of the thread.
   */
  name: string
}

interface ThreadsResponse extends Response {
  body: {
    /**
     * All threads.
     */
    threads: Thread[]
  }
}

interface StackTraceArguments {
  /**
   * Retrieve the stacktrace for this thread.
   */
  threadId: number

  /**
   * The index of the first frame to return; if omitted frames start at 0.
   */
  startFrame?: number

  /**
   * The maximum number of frames to return. If levels is not specified or 0,
   * all frames are returned.
   */
  levels?: number

  /**
   * Specifies details on how to format the returned `StackFrame.name`. The
   * debug adapter may format requested details in any way that would make sense
   * to a developer.
   * The attribute is only honored by a debug adapter if the corresponding
   * capability `supportsValueFormattingOptions` is true.
   */
  format?: StackFrameFormat
}

interface StackTraceResponse extends Response {
  body: {
    /**
     * The frames of the stack frame. If the array has length zero, there are no
     * stack frames available.
     * This means that there is no location information available.
     */
    stackFrames: StackFrame[]

    /**
     * The total number of frames available in the stack. If omitted or if
     * `totalFrames` is larger than the available frames, a client is expected
     * to request frames until a request returns less frames than requested
     * (which indicates the end of the stack). Returning monotonically
     * increasing `totalFrames` values for subsequent requests can be used to
     * enforce paging in the client.
     */
    totalFrames?: number
  }
}

interface StackFrame {
  /**
   * An identifier for the stack frame. It must be unique across all threads.
   * This id can be used to retrieve the scopes of the frame with the `scopes`
   * request or to restart the execution of a stack frame.
   */
  id: number

  /**
   * The name of the stack frame, typically a method name.
   */
  name: string

  /**
   * The source of the frame.
   */
  source?: Source

  /**
   * The line within the source of the frame. If the source attribute is missing
   * or doesn't exist, `line` is 0 and should be ignored by the client.
   */
  line: number

  /**
   * Start position of the range covered by the stack frame. It is measured in
   * UTF-16 code units and the client capability `columnsStartAt1` determines
   * whether it is 0- or 1-based. If attribute `source` is missing or doesn't
   * exist, `column` is 0 and should be ignored by the client.
   */
  column: number

  /**
   * The end line of the range covered by the stack frame.
   */
  endLine?: number

  /**
   * End position of the range covered by the stack frame. It is measured in
   * UTF-16 code units and the client capability `columnsStartAt1` determines
   * whether it is 0- or 1-based.
   */
  endColumn?: number

  /**
   * Indicates whether this frame can be restarted with the `restartFrame`
   * request. Clients should only use this if the debug adapter supports the
   * `restart` request and the corresponding capability `supportsRestartFrame`
   * is true. If a debug adapter has this capability, then `canRestart` defaults
   * to `true` if the property is absent.
   */
  canRestart?: boolean

  /**
   * A memory reference for the current instruction pointer in this frame.
   */
  instructionPointerReference?: string

  /**
   * The module associated with this frame, if any.
   */
  moduleId?: number | string

  /**
   * A hint for how to present this frame in the UI.
   * A value of `label` can be used to indicate that the frame is an artificial
   * frame that is used as a visual label or separator. A value of `subtle` can
   * be used to change the appearance of a frame in a 'subtle' way.
   * Values: 'normal', 'label', 'subtle'
   */
  presentationHint?: 'normal' | 'label' | 'subtle'
}

interface ScopesArguments {
  /**
   * Retrieve the scopes for the stack frame identified by `frameId`. The
   * `frameId` must have been obtained in the current suspended state. See
   * 'Lifetime of Object References' in the Overview section for details.
   */
  frameId: number
}

interface ScopesResponse extends Response {
  body: {
    /**
     * The scopes of the stack frame. If the array has length zero, there are no
     * scopes available.
     */
    scopes: Scope[]
  }
}

interface Scope {
  /**
   * Name of the scope such as 'Arguments', 'Locals', or 'Registers'. This
   * string is shown in the UI as is and can be translated.
   */
  name: string

  /**
   * A hint for how to present this scope in the UI. If this attribute is
   * missing, the scope is shown with a generic UI.
   * Values:
   * 'arguments': Scope contains method arguments.
   * 'locals': Scope contains local variables.
   * 'registers': Scope contains registers. Only a single `registers` scope
   * should be returned from a `scopes` request.
   * 'returnValue': Scope contains one or more return values.
   * etc.
   */
  presentationHint?: 'arguments' | 'locals' | 'registers' | 'returnValue' | string

  /**
   * The variables of this scope can be retrieved by passing the value of
   * `variablesReference` to the `variables` request as long as execution
   * remains suspended. See 'Lifetime of Object References' in the Overview
   * section for details.
   */
  variablesReference: number

  /**
   * The number of named variables in this scope.
   * The client can use this information to present the variables in a paged UI
   * and fetch them in chunks.
   */
  namedVariables?: number

  /**
   * The number of indexed variables in this scope.
   * The client can use this information to present the variables in a paged UI
   * and fetch them in chunks.
   */
  indexedVariables?: number

  /**
   * If true, the number of variables in this scope is large or expensive to
   * retrieve.
   */
  expensive: boolean

  /**
   * The source for this scope.
   */
  source?: Source

  /**
   * The start line of the range covered by this scope.
   */
  line?: number

  /**
   * Start position of the range covered by the scope. It is measured in UTF-16
   * code units and the client capability `columnsStartAt1` determines whether
   * it is 0- or 1-based.
   */
  column?: number

  /**
   * The end line of the range covered by this scope.
   */
  endLine?: number

  /**
   * End position of the range covered by the scope. It is measured in UTF-16
   * code units and the client capability `columnsStartAt1` determines whether
   * it is 0- or 1-based.
   */
  endColumn?: number
}

interface VariablePresentationHint {
  /**
   * The kind of variable. Before introducing additional values, try to use the
   * listed values.
   * Values:
   * 'property': Indicates that the object is a property.
   * 'method': Indicates that the object is a method.
   * 'class': Indicates that the object is a class.
   * 'data': Indicates that the object is data.
   * 'event': Indicates that the object is an event.
   * 'baseClass': Indicates that the object is a base class.
   * 'innerClass': Indicates that the object is an inner class.
   * 'interface': Indicates that the object is an interface.
   * 'mostDerivedClass': Indicates that the object is the most derived class.
   * 'virtual': Indicates that the object is virtual, that means it is a
   * synthetic object introduced by the adapter for rendering purposes, e.g. an
   * index range for large arrays.
   * 'dataBreakpoint': Deprecated: Indicates that a data breakpoint is
   * registered for the object. The `hasDataBreakpoint` attribute should
   * generally be used instead.
   * etc.
   */
  kind?:
    | 'property'
    | 'method'
    | 'class'
    | 'data'
    | 'event'
    | 'baseClass'
    | 'innerClass'
    | 'interface'
    | 'mostDerivedClass'
    | 'virtual'
    | 'dataBreakpoint'
    | string

  /**
   * Set of attributes represented as an array of strings. Before introducing
   * additional values, try to use the listed values.
   * Values:
   * 'static': Indicates that the object is static.
   * 'constant': Indicates that the object is a constant.
   * 'readOnly': Indicates that the object is read only.
   * 'rawString': Indicates that the object is a raw string.
   * 'hasObjectId': Indicates that the object can have an Object ID created for
   * it. This is a vestigial attribute that is used by some clients; 'Object
   * ID's are not specified in the protocol.
   * 'canHaveObjectId': Indicates that the object has an Object ID associated
   * with it. This is a vestigial attribute that is used by some clients;
   * 'Object ID's are not specified in the protocol.
   * 'hasSideEffects': Indicates that the evaluation had side effects.
   * 'hasDataBreakpoint': Indicates that the object has its value tracked by a
   * data breakpoint.
   * etc.
   */
  attributes?: (
    | 'static'
    | 'constant'
    | 'readOnly'
    | 'rawString'
    | 'hasObjectId'
    | 'canHaveObjectId'
    | 'hasSideEffects'
    | 'hasDataBreakpoint'
    | string
  )[]

  /**
   * Visibility of variable. Before introducing additional values, try to use
   * the listed values.
   * Values: 'public', 'private', 'protected', 'internal', 'final', etc.
   */
  visibility?: 'public' | 'private' | 'protected' | 'internal' | 'final' | string

  /**
   * If true, clients can present the variable with a UI that supports a
   * specific gesture to trigger its evaluation.
   * This mechanism can be used for properties that require executing code when
   * retrieving their value and where the code execution can be expensive and/or
   * produce side-effects. A typical example are properties based on a getter
   * function.
   * Please note that in addition to the `lazy` flag, the variable's
   * `variablesReference` is expected to refer to a variable that will provide
   * the value through another `variable` request.
   */
  lazy?: boolean
}

interface Variable {
  /**
   * The variable's name.
   */
  name: string

  /**
   * The variable's value.
   * This can be a multi-line text, e.g. for a function the body of a function.
   * For structured variables (which do not have a simple value), it is
   * recommended to provide a one-line representation of the structured object.
   * This helps to identify the structured object in the collapsed state when
   * its children are not yet visible.
   * An empty string can be used if no value should be shown in the UI.
   */
  value: string

  /**
   * The type of the variable's value. Typically shown in the UI when hovering
   * over the value.
   * This attribute should only be returned by a debug adapter if the
   * corresponding capability `supportsVariableType` is true.
   */
  type?: string

  /**
   * Properties of a variable that can be used to determine how to render the
   * variable in the UI.
   */
  presentationHint?: VariablePresentationHint

  /**
   * The evaluatable name of this variable which can be passed to the `evaluate`
   * request to fetch the variable's value.
   */
  evaluateName?: string

  /**
   * If `variablesReference` is > 0, the variable is structured and its children
   * can be retrieved by passing `variablesReference` to the `variables` request
   * as long as execution remains suspended. See 'Lifetime of Object References'
   * in the Overview section for details.
   */
  variablesReference: number

  /**
   * The number of named child variables.
   * The client can use this information to present the children in a paged UI
   * and fetch them in chunks.
   */
  namedVariables?: number

  /**
   * The number of indexed child variables.
   * The client can use this information to present the children in a paged UI
   * and fetch them in chunks.
   */
  indexedVariables?: number

  /**
   * A memory reference associated with this variable.
   * For pointer type variables, this is generally a reference to the memory
   * address contained in the pointer.
   * For executable data, this reference may later be used in a `disassemble`
   * request.
   * This attribute may be returned by a debug adapter if corresponding
   * capability `supportsMemoryReferences` is true.
   */
  memoryReference?: string

  /**
   * A reference that allows the client to request the location where the
   * variable is declared. This should be present only if the adapter is likely
   * to be able to resolve the location.
   *
   * This reference shares the same lifetime as the `variablesReference`. See
   * 'Lifetime of Object References' in the Overview section for details.
   */
  declarationLocationReference?: number

  /**
   * A reference that allows the client to request the location where the
   * variable's value is declared. For example, if the variable contains a
   * function pointer, the adapter may be able to look up the function's
   * location. This should be present only if the adapter is likely to be able
   * to resolve the location.
   *
   * This reference shares the same lifetime as the `variablesReference`. See
   * 'Lifetime of Object References' in the Overview section for details.
   */
  valueLocationReference?: number
}

interface VariablesArguments {
  /**
   * The variable for which to retrieve its children. The `variablesReference`
   * must have been obtained in the current suspended state. See 'Lifetime of
   * Object References' in the Overview section for details.
   */
  variablesReference: number

  /**
   * Filter to limit the child variables to either named or indexed. If omitted,
   * both types are fetched.
   * Values: 'indexed', 'named'
   */
  filter?: 'indexed' | 'named'

  /**
   * The index of the first variable to return; if omitted children start at 0.
   * The attribute is only honored by a debug adapter if the corresponding
   * capability `supportsVariablePaging` is true.
   */
  start?: number

  /**
   * The number of variables to return. If count is missing or 0, all variables
   * are returned.
   * The attribute is only honored by a debug adapter if the corresponding
   * capability `supportsVariablePaging` is true.
   */
  count?: number

  /**
   * Specifies details on how to format the Variable values.
   * The attribute is only honored by a debug adapter if the corresponding
   * capability `supportsValueFormattingOptions` is true.
   */
  format?: ValueFormat
}

interface VariablesResponse extends Response {
  body: {
    /**
     * All (or a range) of variables for the given variable reference.
     */
    variables: Variable[]
  }
}
