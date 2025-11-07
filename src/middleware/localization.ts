/**
 * Localization and Internationalization for Validation
 * Provides multi-language support for validation error messages
 */

import { Request } from 'express';
import { logger } from '../utils/logger';

/**
 * Supported languages
 */
export type SupportedLanguage = 'en' | 'es' | 'fr' | 'de' | 'it' | 'pt' | 'zh' | 'ja' | 'ko' | 'ru' | 'ar';

/**
 * Error message categories
 */
export type ErrorCategory = 
  | 'validation'
  | 'authentication'
  | 'authorization'
  | 'business_rules'
  | 'security'
  | 'rate_limiting'
  | 'system';

/**
 * Error message structure
 */
export interface LocalizedError {
  code: string;
  category: ErrorCategory;
  severity: 'low' | 'medium' | 'high' | 'critical';
  translations: Record<SupportedLanguage, string>;
  defaultParams?: Record<string, any>;
}

/**
 * Comprehensive error message database
 */
export const errorMessages: Record<string, LocalizedError> = {
  // Validation Errors
  FIELD_REQUIRED: {
    code: 'FIELD_REQUIRED',
    category: 'validation',
    severity: 'medium',
    translations: {
      en: 'This field is required',
      es: 'Este campo es obligatorio',
      fr: 'Ce champ est requis',
      de: 'Dieses Feld ist erforderlich',
      it: 'Questo campo è obbligatorio',
      pt: 'Este campo é obrigatório',
      zh: '此字段为必填项',
      ja: 'このフィールドは必須です',
      ko: '이 필드는 필수입니다',
      ru: 'Это поле обязательно',
      ar: 'هذا الحقل مطلوب'
    }
  },

  EMAIL_INVALID: {
    code: 'EMAIL_INVALID',
    category: 'validation',
    severity: 'medium',
    translations: {
      en: 'Please provide a valid email address',
      es: 'Por favor proporcione una dirección de correo electrónico válida',
      fr: 'Veuillez fournir une adresse e-mail valide',
      de: 'Bitte geben Sie eine gültige E-Mail-Adresse ein',
      it: 'Si prega di fornire un indirizzo email valido',
      pt: 'Por favor, forneça um endereço de email válido',
      zh: '请提供有效的电子邮件地址',
      ja: '有効なメールアドレスを入力してください',
      ko: '유효한 이메일 주소를 입력하세요',
      ru: 'Пожалуйста, введите действительный адрес электронной почты',
      ar: 'يرجى تقديم عنوان بريد إلكتروني صالح'
    }
  },

  PASSWORD_TOO_SHORT: {
    code: 'PASSWORD_TOO_SHORT',
    category: 'validation',
    severity: 'high',
    translations: {
      en: 'Password must be at least {minLength} characters long',
      es: 'La contraseña debe tener al menos {minLength} caracteres',
      fr: 'Le mot de passe doit contenir au moins {minLength} caractères',
      de: 'Das Passwort muss mindestens {minLength} Zeichen lang sein',
      it: 'La password deve essere lunga almeno {minLength} caratteri',
      pt: 'A senha deve ter pelo menos {minLength} caracteres',
      zh: '密码长度至少为 {minLength} 个字符',
      ja: 'パスワードは{minLength}文字以上である必要があります',
      ko: '비밀번호는 최소 {minLength}자 이상이어야 합니다',
      ru: 'Пароль должен содержать не менее {minLength} символов',
      ar: 'يجب أن تكون كلمة المرور {minLength} أحرف على الأقل'
    },
    defaultParams: { minLength: 8 }
  },

  PASSWORD_COMPLEXITY: {
    code: 'PASSWORD_COMPLEXITY',
    category: 'validation',
    severity: 'high',
    translations: {
      en: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      es: 'La contraseña debe contener al menos una letra mayúscula, una minúscula, un número y un caracter especial',
      fr: 'Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial',
      de: 'Das Passwort muss mindestens einen Großbuchstaben, einen Kleinbuchstaben, eine Zahl und ein Sonderzeichen enthalten',
      it: 'La password deve contenere almeno una lettera maiuscola, una minuscola, un numero e un carattere speciale',
      pt: 'A senha deve conter pelo menos uma letra maiúscula, uma minúscula, um número e um caractere especial',
      zh: '密码必须包含至少一个大写字母、一个小写字母、一个数字和一个特殊字符',
      ja: 'パスワードには、大文字、小文字、数字、特殊文字をそれぞれ少なくとも1つ含める必要があります',
      ko: '비밀번호는 대문자, 소문자, 숫자, 특수문자를 각각 최소 1개씩 포함해야 합니다',
      ru: 'Пароль должен содержать как минимум одну заглавную букву, одну строчную букву, одну цифру и один специальный символ',
      ar: 'يجب أن تحتوي كلمة المرور على حرف كبير واحد على الأقل وحرف صغير ورقم ورمز خاص'
    }
  },

  PASSWORDS_NO_MATCH: {
    code: 'PASSWORDS_NO_MATCH',
    category: 'validation',
    severity: 'medium',
    translations: {
      en: 'Passwords do not match',
      es: 'Las contraseñas no coinciden',
      fr: 'Les mots de passe ne correspondent pas',
      de: 'Die Passwörter stimmen nicht überein',
      it: 'Le password non corrispondono',
      pt: 'As senhas não coincidem',
      zh: '密码不匹配',
      ja: 'パスワードが一致しません',
      ko: '비밀번호가 일치하지 않습니다',
      ru: 'Пароли не совпадают',
      ar: 'كلمات المرور غير متطابقة'
    }
  },

  // Business Rule Errors
  EMAIL_DOMAIN_NOT_ALLOWED: {
    code: 'EMAIL_DOMAIN_NOT_ALLOWED',
    category: 'business_rules',
    severity: 'medium',
    translations: {
      en: 'Email domain {domain} is not allowed',
      es: 'El dominio de correo {domain} no está permitido',
      fr: 'Le domaine de messagerie {domain} n\'est pas autorisé',
      de: 'E-Mail-Domain {domain} ist nicht erlaubt',
      it: 'Il dominio email {domain} non è consentito',
      pt: 'O domínio de email {domain} não é permitido',
      zh: '不允许使用电子邮件域 {domain}',
      ja: 'メールドメイン {domain} は許可されていません',
      ko: '이메일 도메인 {domain}은(는) 허용되지 않습니다',
      ru: 'Почтовый домен {domain} не разрешен',
      ar: 'نطاق البريد الإلكتروني {domain} غير مسموح'
    }
  },

  USERNAME_RESERVED: {
    code: 'USERNAME_RESERVED',
    category: 'business_rules',
    severity: 'medium',
    translations: {
      en: 'This username is reserved and cannot be used',
      es: 'Este nombre de usuario está reservado y no se puede usar',
      fr: 'Ce nom d\'utilisateur est réservé et ne peut pas être utilisé',
      de: 'Dieser Benutzername ist reserviert und kann nicht verwendet werden',
      it: 'Questo nome utente è riservato e non può essere utilizzato',
      pt: 'Este nome de usuário é reservado e não pode ser usado',
      zh: '此用户名已被保留，无法使用',
      ja: 'このユーザー名は予約されており、使用できません',
      ko: '이 사용자명은 예약되어 있어 사용할 수 없습니다',
      ru: 'Это имя пользователя зарезервировано и не может быть использовано',
      ar: 'اسم المستخدم هذا محجوز ولا يمكن استخدامه'
    }
  },

  PASSWORD_COMMON: {
    code: 'PASSWORD_COMMON',
    category: 'business_rules',
    severity: 'medium',
    translations: {
      en: 'This password is too common. Please choose a more secure password',
      es: 'Esta contraseña es demasiado común. Por favor elija una contraseña más segura',
      fr: 'Ce mot de passe est trop commun. Veuillez choisir un mot de passe plus sécurisé',
      de: 'Dieses Passwort ist zu häufig verwendet. Bitte wählen Sie ein sichereres Passwort',
      it: 'Questa password è troppo comune. Si prega di scegliere una password più sicura',
      pt: 'Esta senha é muito comum. Por favor, escolha uma senha mais segura',
      zh: '此密码过于常见。请选择更安全的密码',
      ja: 'このパスワードは一般的すぎます。より安全なパスワードを選択してください',
      ko: '이 비밀번호는 너무 일반적입니다. 더 안전한 비밀번호를 선택하세요',
      ru: 'Этот пароль слишком распространенный. Пожалуйста, выберите более безопасный пароль',
      ar: 'كلمة المرور هذه شائعة جداً. يرجى اختيار كلمة مرور أكثر أماناً'
    }
  },

  PROFANITY_DETECTED: {
    code: 'PROFANITY_DETECTED',
    category: 'business_rules',
    severity: 'medium',
    translations: {
      en: 'Inappropriate content detected. Please use appropriate language',
      es: 'Contenido inapropiado detectado. Por favor use un lenguaje apropiado',
      fr: 'Contenu inapproprié détecté. Veuillez utiliser un langage approprié',
      de: 'Unangemessener Inhalt erkannt. Bitte verwenden Sie angemessene Sprache',
      it: 'Contenuto inappropriato rilevato. Si prega di utilizzare un linguaggio appropriato',
      pt: 'Conteúdo inapropriado detectado. Por favor, use linguagem apropriada',
      zh: '检测到不当内容。请使用适当的语言',
      ja: '不適切なコンテンツが検出されました。適切な言葉を使用してください',
      ko: '부적절한 내용이 감지되었습니다. 적절한 언어를 사용하세요',
      ru: 'Обнаружен неподходящий контент. Пожалуйста, используйте подходящий язык',
      ar: 'تم اكتشاف محتوى غير لائق. يرجى استخدام لغة مناسبة'
    }
  },

  // Security Errors
  XSS_ATTEMPT_DETECTED: {
    code: 'XSS_ATTEMPT_DETECTED',
    category: 'security',
    severity: 'critical',
    translations: {
      en: 'Potential security threat detected. Request blocked',
      es: 'Amenaza de seguridad potencial detectada. Solicitud bloqueada',
      fr: 'Menace de sécurité potentielle détectée. Demande bloquée',
      de: 'Potentielle Sicherheitsbedrohung erkannt. Anfrage blockiert',
      it: 'Rilevata potenziale minaccia alla sicurezza. Richiesta bloccata',
      pt: 'Ameaça de segurança potencial detectada. Solicitação bloqueada',
      zh: '检测到潜在安全威胁。请求已被阻止',
      ja: '潜在的なセキュリティ脅威が検出されました。リクエストがブロックされました',
      ko: '잠재적인 보안 위협이 감지되었습니다. 요청이 차단되었습니다',
      ru: 'Обнаружена потенциальная угроза безопасности. Запрос заблокирован',
      ar: 'تم اكتشاف تهديد أمني محتمل. تم حظر الطلب'
    }
  },

  SQL_INJECTION_DETECTED: {
    code: 'SQL_INJECTION_DETECTED',
    category: 'security',
    severity: 'critical',
    translations: {
      en: 'SQL injection attempt detected. Request blocked',
      es: 'Intento de inyección SQL detectado. Solicitud bloqueada',
      fr: 'Tentative d\'injection SQL détectée. Demande bloquée',
      de: 'SQL-Injection-Versuch erkannt. Anfrage blockiert',
      it: 'Rilevato tentativo di SQL injection. Richiesta bloccata',
      pt: 'Tentativa de injeção SQL detectada. Solicitação bloqueada',
      zh: '检测到SQL注入尝试。请求已被阻止',
      ja: 'SQLインジェクション試行が検出されました。リクエストがブロックされました',
      ko: 'SQL 인젝션 시도가 감지되었습니다. 요청이 차단되었습니다',
      ru: 'Обнаружена попытка SQL-инъекции. Запрос заблокирован',
      ar: 'تم اكتشاف محاولة حقن SQL. تم حظر الطلب'
    }
  },

  // Rate Limiting
  RATE_LIMIT_EXCEEDED: {
    code: 'RATE_LIMIT_EXCEEDED',
    category: 'rate_limiting',
    severity: 'medium',
    translations: {
      en: 'Too many requests. Please try again in {retryAfter} seconds',
      es: 'Demasiadas solicitudes. Por favor intente de nuevo en {retryAfter} segundos',
      fr: 'Trop de requêtes. Veuillez réessayer dans {retryAfter} secondes',
      de: 'Zu viele Anfragen. Bitte versuchen Sie es in {retryAfter} Sekunden erneut',
      it: 'Troppe richieste. Si prega di riprovare tra {retryAfter} secondi',
      pt: 'Muitas solicitações. Tente novamente em {retryAfter} segundos',
      zh: '请求过多。请在 {retryAfter} 秒后重试',
      ja: 'リクエストが多すぎます。{retryAfter}秒後に再試行してください',
      ko: '요청이 너무 많습니다. {retryAfter}초 후에 다시 시도하세요',
      ru: 'Слишком много запросов. Пожалуйста, попробуйте снова через {retryAfter} секунд',
      ar: 'طلبات كثيرة جداً. يرجى المحاولة مرة أخرى خلال {retryAfter} ثانية'
    }
  },

  // Authentication
  INVALID_CREDENTIALS: {
    code: 'INVALID_CREDENTIALS',
    category: 'authentication',
    severity: 'medium',
    translations: {
      en: 'Invalid email or password',
      es: 'Correo electrónico o contraseña inválidos',
      fr: 'E-mail ou mot de passe invalide',
      de: 'Ungültige E-Mail oder Passwort',
      it: 'Email o password non validi',
      pt: 'Email ou senha inválidos',
      zh: '电子邮件或密码无效',
      ja: '無効なメールアドレスまたはパスワード',
      ko: '잘못된 이메일 또는 비밀번호',
      ru: 'Неверный email или пароль',
      ar: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
    }
  },

  ACCOUNT_LOCKED: {
    code: 'ACCOUNT_LOCKED',
    category: 'authentication',
    severity: 'high',
    translations: {
      en: 'Account is temporarily locked due to multiple failed login attempts',
      es: 'La cuenta está temporalmente bloqueada debido a múltiples intentos de inicio de sesión fallidos',
      fr: 'Le compte est temporairement verrouillé en raison de plusieurs tentatives de connexion échouées',
      de: 'Konto ist aufgrund mehrerer fehlgeschlagener Anmeldeversuche vorübergehend gesperrt',
      it: 'L\'account è temporaneamente bloccato a causa di più tentativi di accesso falliti',
      pt: 'A conta está temporariamente bloqueada devido a múltiplas tentativas de login falhadas',
      zh: '由于多次登录失败，账户已暂时锁定',
      ja: '複数回のログイン試行の失敗により、アカウントが一時的にロックされています',
      ko: '여러 번의 로그인 실패로 인해 계정이 일시적으로 잠겨 있습니다',
      ru: 'Аккаунт временно заблокирован из-за множественных неудачных попыток входа',
      ar: 'الحساب مغلق مؤقتاً بسبب عدة محاولات دخول فاشلة'
    }
  },

  // Additional Business Rule Errors
  PHONE_NUMBER_INVALID: {
    code: 'PHONE_NUMBER_INVALID',
    category: 'business_rules',
    severity: 'medium',
    translations: {
      en: 'Invalid phone number format',
      es: 'Formato de número de teléfono inválido',
      fr: 'Format de numéro de téléphone invalide',
      de: 'Ungültiges Telefonnummernformat',
      it: 'Formato numero di telefono non valido',
      pt: 'Formato de número de telefone inválido',
      zh: '电话号码格式无效',
      ja: '電話番号の形式が無効です',
      ko: '전화번호 형식이 잘못되었습니다',
      ru: 'Неверный формат номера телефона',
      ar: 'تنسيق رقم الهاتف غير صحيح'
    }
  },

  AGE_INVALID: {
    code: 'AGE_INVALID',
    category: 'business_rules',
    severity: 'medium',
    translations: {
      en: 'Age must be between {minAge} and {maxAge} years',
      es: 'La edad debe estar entre {minAge} y {maxAge} años',
      fr: 'L\'âge doit être entre {minAge} et {maxAge} ans',
      de: 'Das Alter muss zwischen {minAge} und {maxAge} Jahren liegen',
      it: 'L\'età deve essere compresa tra {minAge} e {maxAge} anni',
      pt: 'A idade deve estar entre {minAge} e {maxAge} anos',
      zh: '年龄必须在 {minAge} 到 {maxAge} 岁之间',
      ja: '年齢は{minAge}歳から{maxAge}歳の間である必要があります',
      ko: '나이는 {minAge}세에서 {maxAge}세 사이여야 합니다',
      ru: 'Возраст должен быть от {minAge} до {maxAge} лет',
      ar: 'يجب أن يكون العمر بين {minAge} و {maxAge} سنة'
    },
    defaultParams: { minAge: 13, maxAge: 120 }
  },

  DATE_RANGE_INVALID: {
    code: 'DATE_RANGE_INVALID',
    category: 'business_rules',
    severity: 'medium',
    translations: {
      en: 'Date is outside the allowed range',
      es: 'La fecha está fuera del rango permitido',
      fr: 'La date est en dehors de la plage autorisée',
      de: 'Das Datum liegt außerhalb des zulässigen Bereichs',
      it: 'La data è al di fuori dell\'intervallo consentito',
      pt: 'A data está fora do intervalo permitido',
      zh: '日期超出了允许的范围',
      ja: '日付が許可された範囲外です',
      ko: '날짜가 허용된 범위를 벗어났습니다',
      ru: 'Дата находится вне допустимого диапазона',
      ar: 'التاريخ خارج النطاق المسموح'
    }
  }
};

/**
 * Language detection from request
 */
export const detectLanguage = (req: Request): SupportedLanguage => {
  // 1. Check URL parameter
  if (req.query.lang && typeof req.query.lang === 'string') {
    const lang = req.query.lang as SupportedLanguage;
    if (Object.keys(errorMessages.FIELD_REQUIRED.translations).includes(lang)) {
      return lang;
    }
  }

  // 2. Check custom header
  const customLang = req.get('X-Language') as SupportedLanguage;
  if (customLang && Object.keys(errorMessages.FIELD_REQUIRED.translations).includes(customLang)) {
    return customLang;
  }

  // 3. Check Accept-Language header
  const acceptLanguage = req.get('Accept-Language');
  if (acceptLanguage) {
    const preferredLanguages = acceptLanguage
      .split(',')
      .map(lang => lang.split(';')[0].trim().toLowerCase());

    for (const lang of preferredLanguages) {
      // Check exact match
      if (Object.keys(errorMessages.FIELD_REQUIRED.translations).includes(lang as SupportedLanguage)) {
        return lang as SupportedLanguage;
      }
      
      // Check language prefix (e.g., 'en-US' -> 'en')
      const langPrefix = lang.split('-')[0];
      if (Object.keys(errorMessages.FIELD_REQUIRED.translations).includes(langPrefix as SupportedLanguage)) {
        return langPrefix as SupportedLanguage;
      }
    }
  }

  // 4. Default to English
  return 'en';
};

/**
 * Get localized error message
 */
export const getLocalizedMessage = (
  errorCode: string,
  language: SupportedLanguage = 'en',
  params: Record<string, any> = {}
): string => {
  const errorDef = errorMessages[errorCode];
  
  if (!errorDef) {
    logger.warn('Unknown error code requested', { errorCode, language });
    return errorMessages.FIELD_REQUIRED.translations[language] || errorMessages.FIELD_REQUIRED.translations.en;
  }

  let message = errorDef.translations[language] || errorDef.translations.en;
  
  // Replace parameters in message
  const allParams = { ...errorDef.defaultParams, ...params };
  for (const [key, value] of Object.entries(allParams)) {
    message = message.replace(new RegExp(`\\{${key}\\}`, 'g'), String(value));
  }

  return message;
};

/**
 * Get localized error object
 */
export const getLocalizedError = (
  errorCode: string,
  language: SupportedLanguage = 'en',
  params: Record<string, any> = {}
): {
  code: string;
  message: string;
  category: ErrorCategory;
  severity: 'low' | 'medium' | 'high' | 'critical';
} => {
  const errorDef = errorMessages[errorCode];
  
  if (!errorDef) {
    return {
      code: 'UNKNOWN_ERROR',
      message: 'An unknown error occurred',
      category: 'system',
      severity: 'medium'
    };
  }

  return {
    code: errorDef.code,
    message: getLocalizedMessage(errorCode, language, params),
    category: errorDef.category,
    severity: errorDef.severity
  };
};

/**
 * Create localized validation error response
 */
export const createValidationErrorResponse = (
  errors: Array<{
    field: string;
    code: string;
    params?: Record<string, any>;
  }>,
  language: SupportedLanguage = 'en'
) => {
  return {
    error: 'Validation failed',
    message: getLocalizedMessage('FIELD_REQUIRED', language),
    details: errors.map(error => ({
      field: error.field,
      code: error.code,
      message: getLocalizedMessage(error.code, language, error.params),
      severity: errorMessages[error.code]?.severity || 'medium'
    })),
    language,
    timestamp: new Date().toISOString()
  };
};

/**
 * Middleware to add localization context to request
 */
export const localizationMiddleware = () => {
  return (req: Request, res: any, next: any) => {
    const language = detectLanguage(req);
    (req as any).language = language;
    (req as any).getLocalizedMessage = (code: string, params?: Record<string, any>) => 
      getLocalizedMessage(code, language, params);
    (req as any).getLocalizedError = (code: string, params?: Record<string, any>) => 
      getLocalizedError(code, language, params);
    
    // Set response language header
    res.setHeader('Content-Language', language);
    
    next();
  };
};

export default {
  errorMessages,
  detectLanguage,
  getLocalizedMessage,
  getLocalizedError,
  createValidationErrorResponse,
  localizationMiddleware
};