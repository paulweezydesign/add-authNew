/**
 * Main Password Security Module
 * Comprehensive password security implementation for authentication system
 */

export interface PasswordConfig {
  readonly saltRounds: number;
  readonly minLength: number;
  readonly requireUppercase: boolean;
  readonly requireLowercase: boolean;
  readonly requireNumbers: boolean;
  readonly requireSpecialChars: boolean;
  readonly specialChars: string;
  readonly historyCount: number;
}

export interface PasswordValidationResult {
  readonly isValid: boolean;
  readonly errors: string[];
  readonly strength: PasswordStrength;
}

export enum PasswordStrength {
  WEAK = 'weak',
  MEDIUM = 'medium',
  STRONG = 'strong',
  VERY_STRONG = 'very_strong'
}

export const DEFAULT_PASSWORD_CONFIG: PasswordConfig = {
  saltRounds: 12,
  minLength: 8,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  historyCount: 5
};

/**
 * Password Security Manager
 * Main interface for all password security operations
 */
export class PasswordSecurityManager {
  private readonly config: PasswordConfig;

  constructor(config?: Partial<PasswordConfig>) {
    this.config = { ...DEFAULT_PASSWORD_CONFIG, ...config };
  }

  /**
   * Validate password strength against configured rules
   */
  validatePassword(password: string): PasswordValidationResult {
    const errors: string[] = [];

    if (!password) {
      errors.push('Password is required');
      return { isValid: false, errors, strength: PasswordStrength.WEAK };
    }

    if (password.length < this.config.minLength) {
      errors.push(`Password must be at least ${this.config.minLength} characters long`);
    }

    if (this.config.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (this.config.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (this.config.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (this.config.requireSpecialChars) {
      const specialCharsRegex = new RegExp(`[${this.escapeRegExp(this.config.specialChars)}]`);
      if (!specialCharsRegex.test(password)) {
        errors.push(`Password must contain at least one special character`);
      }
    }

    const strength = this.assessPasswordStrength(password);

    return {
      isValid: errors.length === 0,
      errors,
      strength
    };
  }

  /**
   * Check if password meets minimum requirements
   */
  meetsMinimumRequirements(password: string): boolean {
    const validation = this.validatePassword(password);
    return validation.isValid && validation.strength !== PasswordStrength.WEAK;
  }

  /**
   * Get password configuration
   */
  getConfig(): PasswordConfig {
    return { ...this.config };
  }

  /**
   * Assess password strength based on various criteria
   */
  private assessPasswordStrength(password: string): PasswordStrength {
    let score = 0;

    // Length scoring
    if (password.length >= this.config.minLength) score += 2;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    // Character variety
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (new RegExp(`[${this.escapeRegExp(this.config.specialChars)}]`).test(password)) score += 1;

    // Unique characters
    const uniqueChars = new Set(password.toLowerCase()).size;
    if (uniqueChars >= password.length * 0.7) score += 1;

    // Determine strength based on score
    if (score <= 3) return PasswordStrength.WEAK;
    if (score <= 6) return PasswordStrength.MEDIUM;
    if (score <= 8) return PasswordStrength.STRONG;
    return PasswordStrength.VERY_STRONG;
  }

  /**
   * Escape special characters for regex
   */
  private escapeRegExp(string: string): string {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}

// Create default instance
export const defaultPasswordSecurity = new PasswordSecurityManager();