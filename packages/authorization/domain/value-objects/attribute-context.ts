export type AttributeValue =
  | string
  | number
  | boolean
  | Date
  | readonly AttributeValue[]
  | AttributeRecord;

export interface AttributeRecord {
  readonly [key: string]: AttributeValue;
}

export type AttributeBag = Readonly<Record<string, AttributeValue | undefined>>;
export type AttributeBagName = "subject" | "resource" | "action" | "environment";
export type AttributeValueType = "string" | "number" | "boolean" | "date" | "array";

export interface AttributeBags {
  readonly subject: AttributeBag;
  readonly resource: AttributeBag;
  readonly action: AttributeBag;
  readonly environment: AttributeBag;
}

const BAG_NAMES: readonly AttributeBagName[] = ["subject", "resource", "action", "environment"];

function cloneValue(value: AttributeValue): AttributeValue {
  if (value instanceof Date) return new Date(value.getTime());
  if (Array.isArray(value)) return Object.freeze(value.map((item) => cloneValue(item)));
  if (typeof value === "object") return cloneBag(value as AttributeRecord);
  return value;
}

function cloneBag(bag: AttributeBag): AttributeBag {
  const copy: Record<string, AttributeValue> = {};
  for (const [key, value] of Object.entries(bag)) {
    if (value !== undefined) copy[key] = cloneValue(value);
  }
  return Object.freeze(copy);
}

function matchesType(value: AttributeValue, type: AttributeValueType): boolean {
  switch (type) {
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "boolean":
      return typeof value === "boolean";
    case "date":
      return value instanceof Date && !Number.isNaN(value.getTime());
    case "array":
      return Array.isArray(value);
  }
}

/**
 * Immutable, validated request attributes organized using the standard ABAC
 * subject/resource/action/environment vocabulary. Reads are safe for missing
 * paths and return undefined instead of turning ordinary absence into an
 * exception or a grant.
 */
export class AttributeContext {
  readonly subject: AttributeBag;
  readonly resource: AttributeBag;
  readonly action: AttributeBag;
  readonly environment: AttributeBag;

  constructor(bags: Partial<AttributeBags> = {}) {
    for (const name of BAG_NAMES) {
      const bag = Object.hasOwn(bags, name) ? bags[name] : {};
      if (bag === undefined) {
        Object.defineProperty(this, name, {
          value: Object.freeze({}),
          enumerable: true,
          writable: false,
          configurable: false,
        });
        continue;
      }
      if (bag === null || typeof bag !== "object" || Array.isArray(bag)) {
        throw new TypeError(`${name} attributes must be an object.`);
      }
      Object.defineProperty(this, name, {
        value: cloneBag(bag),
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
    Object.freeze(this);
  }

  get(bag: AttributeBagName, path: string): AttributeValue | undefined {
    if (!path) return undefined;
    let current: AttributeValue | undefined = this[bag];
    for (const segment of path.split(".")) {
      if (!segment || current === null || typeof current !== "object" || current instanceof Date) {
        return undefined;
      }
      current = (current as AttributeRecord)[segment];
      if (current === undefined) return undefined;
    }
    return current;
  }

  getTyped<T extends AttributeValueType>(
    bag: AttributeBagName,
    path: string,
    type: T,
  ): Extract<AttributeValue, T extends "string" ? string : T extends "number" ? number : T extends "boolean" ? boolean : T extends "date" ? Date : readonly AttributeValue[]> | undefined {
    const value = this.get(bag, path);
    return value !== undefined && matchesType(value, type) ? (value as never) : undefined;
  }

  getString(bag: AttributeBagName, path: string): string | undefined {
    return this.getTyped(bag, path, "string");
  }

  getNumber(bag: AttributeBagName, path: string): number | undefined {
    return this.getTyped(bag, path, "number");
  }

  getBoolean(bag: AttributeBagName, path: string): boolean | undefined {
    return this.getTyped(bag, path, "boolean");
  }

  getDate(bag: AttributeBagName, path: string): Date | undefined {
    return this.getTyped(bag, path, "date");
  }

  getArray(bag: AttributeBagName, path: string): readonly AttributeValue[] | undefined {
    return this.getTyped(bag, path, "array");
  }

  toBags(): AttributeBags {
    return {
      subject: cloneBag(this.subject),
      resource: cloneBag(this.resource),
      action: cloneBag(this.action),
      environment: cloneBag(this.environment),
    };
/**
 * A value an attribute may hold. Dates get their own case (rather than
 * collapsing to a number/string timestamp) because time-window conditions
 * (`resource.availableFrom`, `env.now`) are a named use case in the DSL
 * design (Issue 142) and deserve a type that survives round-tripping through
 * this context, not a convention callers have to remember to parse.
 */
export type AttributeValue = string | number | boolean | Date | readonly (string | number)[];

/** One attribute bag: a flat, typed key/value map. */
export type AttributeBag = Readonly<Record<string, AttributeValue>>;

/** The four categories every policy condition may reference — see NIST SP 800-162. */
export type AttributeCategory = "subject" | "resource" | "action" | "environment";

function isAttributeCategory(value: string): value is AttributeCategory {
  return (
    value === "subject" || value === "resource" || value === "action" || value === "environment"
  );
}

/**
 * Everything a policy condition might condition on, bundled into the four
 * categories ABAC theory (and NIST SP 800-162) splits attributes into:
 * `subject` (the acting principal), `resource` (the target), `action` (the
 * operation being attempted), and `environment` (time, IP, request
 * metadata).
 *
 * Deliberately independent of *where* each bag's values came from — that is
 * an `AttributeProvider`'s job (Issue 145, not yet built), a different
 * concern this value object has no opinion about. `AttributeContext` is
 * just the shape the evaluation engine (Issue 146) evaluates a
 * {@link import("./condition.js").Condition} tree against, however it was
 * assembled — by a real provider pipeline once Issue 145 lands, or by hand
 * (as `AuthorizeAction`, Issue 153, currently does) until then.
 */
export class AttributeContext {
  private readonly bags: Readonly<Record<AttributeCategory, AttributeBag>>;

  private constructor(bags: Readonly<Record<AttributeCategory, AttributeBag>>) {
    this.bags = bags;
  }

  static create(bags: {
    subject?: AttributeBag;
    resource?: AttributeBag;
    action?: AttributeBag;
    environment?: AttributeBag;
  }): AttributeContext {
    return new AttributeContext({
      subject: bags.subject ?? {},
      resource: bags.resource ?? {},
      action: bags.action ?? {},
      environment: bags.environment ?? {},
    });
  }

  /**
   * Looks up `key` within `category`. Returns `undefined` for a missing
   * attribute rather than throwing — per Issue 144's acceptance criteria, a
   * policy referencing an attribute nobody supplied is an expected outcome
   * (the attribute genuinely doesn't apply to this request) the evaluation
   * engine has defined behavior for, not an error condition.
   */
  get(category: AttributeCategory, key: string): AttributeValue | undefined {
    return this.bags[category][key];
  }

  /**
   * Resolves a dotted path (`"resource.ownerId"`) against the four bags,
   * the addressing scheme {@link import("./condition.js").ComparisonCondition}
   * uses. Returns `undefined` for an unrecognized category or a missing key
   * within a recognized one — both are "no such attribute," and the caller
   * (the evaluation engine) treats them identically.
   */
  resolve(path: string): AttributeValue | undefined {
    const separatorIndex = path.indexOf(".");
    if (separatorIndex === -1) {
      return undefined;
    }

    const category = path.slice(0, separatorIndex);
    const key = path.slice(separatorIndex + 1);
    if (!isAttributeCategory(category)) {
      return undefined;
    }

    return this.get(category, key);
  }
}
