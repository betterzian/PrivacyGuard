# Details

Date : 2026-03-21 10:08:28

Directory /Users/vis/Documents/GitHub/PrivacyGuard/privacyguard

Total : 75 files,  11652 codes, 1097 comments, 1422 blanks, all 14171 lines

[Summary](results.md) / Details / [Diff Summary](diff.md) / [Diff Details](diff-details.md)

## Files
| filename | language | code | comment | blank | total |
| :--- | :--- | ---: | ---: | ---: | ---: |
| [privacyguard/\_\_init\_\_.py](/privacyguard/__init__.py) | Python | 3 | 1 | 3 | 7 |
| [privacyguard/api/\_\_init\_\_.py](/privacyguard/api/__init__.py) | Python | 7 | 1 | 3 | 11 |
| [privacyguard/api/dto.py](/privacyguard/api/dto.py) | Python | 42 | 28 | 17 | 87 |
| [privacyguard/api/errors.py](/privacyguard/api/errors.py) | Python | 3 | 4 | 8 | 15 |
| [privacyguard/app/\_\_init\_\_.py](/privacyguard/app/__init__.py) | Python | 3 | 0 | 2 | 5 |
| [privacyguard/app/factories.py](/privacyguard/app/factories.py) | Python | 74 | 5 | 11 | 90 |
| [privacyguard/app/persona\_repository.py](/privacyguard/app/persona_repository.py) | Python | 25 | 4 | 8 | 37 |
| [privacyguard/app/pipelines.py](/privacyguard/app/pipelines.py) | Python | 62 | 6 | 10 | 78 |
| [privacyguard/app/privacy\_guard.py](/privacyguard/app/privacy_guard.py) | Python | 100 | 39 | 10 | 149 |
| [privacyguard/app/schemas.py](/privacyguard/app/schemas.py) | Python | 225 | 27 | 70 | 322 |
| [privacyguard/application/\_\_init\_\_.py](/privacyguard/application/__init__.py) | Python | 0 | 1 | 2 | 3 |
| [privacyguard/application/pipelines/\_\_init\_\_.py](/privacyguard/application/pipelines/__init__.py) | Python | 3 | 1 | 4 | 8 |
| [privacyguard/application/pipelines/restore\_pipeline.py](/privacyguard/application/pipelines/restore_pipeline.py) | Python | 60 | 27 | 11 | 98 |
| [privacyguard/application/pipelines/sanitize\_pipeline.py](/privacyguard/application/pipelines/sanitize_pipeline.py) | Python | 202 | 61 | 34 | 297 |
| [privacyguard/application/services/\_\_init\_\_.py](/privacyguard/application/services/__init__.py) | Python | 12 | 1 | 3 | 16 |
| [privacyguard/application/services/decision\_context\_builder.py](/privacyguard/application/services/decision_context_builder.py) | Python | 681 | 204 | 52 | 937 |
| [privacyguard/application/services/placeholder\_allocator.py](/privacyguard/application/services/placeholder_allocator.py) | Python | 75 | 3 | 15 | 93 |
| [privacyguard/application/services/replacement\_service.py](/privacyguard/application/services/replacement_service.py) | Python | 40 | 3 | 5 | 48 |
| [privacyguard/application/services/resolver\_service.py](/privacyguard/application/services/resolver_service.py) | Python | 494 | 60 | 50 | 604 |
| [privacyguard/application/services/session\_service.py](/privacyguard/application/services/session_service.py) | Python | 171 | 65 | 21 | 257 |
| [privacyguard/bootstrap/\_\_init\_\_.py](/privacyguard/bootstrap/__init__.py) | Python | 5 | 1 | 3 | 9 |
| [privacyguard/bootstrap/factories.py](/privacyguard/bootstrap/factories.py) | Python | 110 | 24 | 35 | 169 |
| [privacyguard/bootstrap/mode\_config.py](/privacyguard/bootstrap/mode_config.py) | Python | 33 | 6 | 12 | 51 |
| [privacyguard/bootstrap/registry.py](/privacyguard/bootstrap/registry.py) | Python | 39 | 11 | 18 | 68 |
| [privacyguard/domain/\_\_init\_\_.py](/privacyguard/domain/__init__.py) | Python | 0 | 1 | 2 | 3 |
| [privacyguard/domain/enums.py](/privacyguard/domain/enums.py) | Python | 25 | 5 | 14 | 44 |
| [privacyguard/domain/interfaces/\_\_init\_\_.py](/privacyguard/domain/interfaces/__init__.py) | Python | 18 | 1 | 3 | 22 |
| [privacyguard/domain/interfaces/decision\_engine.py](/privacyguard/domain/interfaces/decision_engine.py) | Python | 6 | 3 | 6 | 15 |
| [privacyguard/domain/interfaces/mapping\_store.py](/privacyguard/domain/interfaces/mapping_store.py) | Python | 7 | 6 | 9 | 22 |
| [privacyguard/domain/interfaces/ocr\_engine.py](/privacyguard/domain/interfaces/ocr_engine.py) | Python | 4 | 3 | 6 | 13 |
| [privacyguard/domain/interfaces/persona\_repository.py](/privacyguard/domain/interfaces/persona_repository.py) | Python | 7 | 5 | 8 | 20 |
| [privacyguard/domain/interfaces/pii\_detector.py](/privacyguard/domain/interfaces/pii_detector.py) | Python | 5 | 3 | 6 | 14 |
| [privacyguard/domain/interfaces/rendering\_engine.py](/privacyguard/domain/interfaces/rendering_engine.py) | Python | 12 | 4 | 7 | 23 |
| [privacyguard/domain/interfaces/restoration\_module.py](/privacyguard/domain/interfaces/restoration_module.py) | Python | 5 | 3 | 6 | 14 |
| [privacyguard/domain/interfaces/screenshot\_fill\_strategy.py](/privacyguard/domain/interfaces/screenshot_fill_strategy.py) | Python | 10 | 9 | 6 | 25 |
| [privacyguard/domain/models/\_\_init\_\_.py](/privacyguard/domain/models/__init__.py) | Python | 30 | 1 | 3 | 34 |
| [privacyguard/domain/models/action.py](/privacyguard/domain/models/action.py) | Python | 5 | 2 | 6 | 13 |
| [privacyguard/domain/models/decision.py](/privacyguard/domain/models/decision.py) | Python | 29 | 4 | 11 | 44 |
| [privacyguard/domain/models/decision\_context.py](/privacyguard/domain/models/decision_context.py) | Python | 76 | 5 | 16 | 97 |
| [privacyguard/domain/models/mapping.py](/privacyguard/domain/models/mapping.py) | Python | 33 | 4 | 13 | 50 |
| [privacyguard/domain/models/ocr.py](/privacyguard/domain/models/ocr.py) | Python | 57 | 6 | 16 | 79 |
| [privacyguard/domain/models/persona.py](/privacyguard/domain/models/persona.py) | Python | 11 | 3 | 9 | 23 |
| [privacyguard/domain/models/pii.py](/privacyguard/domain/models/pii.py) | Python | 16 | 2 | 6 | 24 |
| [privacyguard/domain/policies/\_\_init\_\_.py](/privacyguard/domain/policies/__init__.py) | Python | 2 | 1 | 4 | 7 |
| [privacyguard/domain/policies/constraint\_resolver.py](/privacyguard/domain/policies/constraint_resolver.py) | Python | 107 | 6 | 12 | 125 |
| [privacyguard/infrastructure/\_\_init\_\_.py](/privacyguard/infrastructure/__init__.py) | Python | 0 | 1 | 2 | 3 |
| [privacyguard/infrastructure/decision/\_\_init\_\_.py](/privacyguard/infrastructure/decision/__init__.py) | Python | 12 | 1 | 3 | 16 |
| [privacyguard/infrastructure/decision/de\_model\_engine.py](/privacyguard/infrastructure/decision/de_model_engine.py) | Python | 199 | 8 | 11 | 218 |
| [privacyguard/infrastructure/decision/de\_model\_runtime.py](/privacyguard/infrastructure/decision/de_model_runtime.py) | Python | 428 | 27 | 55 | 510 |
| [privacyguard/infrastructure/decision/features.py](/privacyguard/infrastructure/decision/features.py) | Python | 703 | 64 | 118 | 885 |
| [privacyguard/infrastructure/decision/label\_only\_engine.py](/privacyguard/infrastructure/decision/label_only_engine.py) | Python | 82 | 5 | 7 | 94 |
| [privacyguard/infrastructure/decision/label\_persona\_mixed\_engine.py](/privacyguard/infrastructure/decision/label_persona_mixed_engine.py) | Python | 127 | 6 | 8 | 141 |
| [privacyguard/infrastructure/decision/tiny\_policy\_net.py](/privacyguard/infrastructure/decision/tiny_policy_net.py) | Python | 328 | 18 | 49 | 395 |
| [privacyguard/infrastructure/decision/tokenizer.py](/privacyguard/infrastructure/decision/tokenizer.py) | Python | 43 | 4 | 12 | 59 |
| [privacyguard/infrastructure/mapping/\_\_init\_\_.py](/privacyguard/infrastructure/mapping/__init__.py) | Python | 3 | 1 | 4 | 8 |
| [privacyguard/infrastructure/mapping/in\_memory\_mapping\_store.py](/privacyguard/infrastructure/mapping/in_memory_mapping_store.py) | Python | 48 | 11 | 14 | 73 |
| [privacyguard/infrastructure/mapping/json\_mapping\_store.py](/privacyguard/infrastructure/mapping/json_mapping_store.py) | Python | 39 | 7 | 11 | 57 |
| [privacyguard/infrastructure/ocr/\_\_init\_\_.py](/privacyguard/infrastructure/ocr/__init__.py) | Python | 2 | 1 | 3 | 6 |
| [privacyguard/infrastructure/ocr/ppocr\_adapter.py](/privacyguard/infrastructure/ocr/ppocr_adapter.py) | Python | 299 | 22 | 44 | 365 |
| [privacyguard/infrastructure/persona/\_\_init\_\_.py](/privacyguard/infrastructure/persona/__init__.py) | Python | 2 | 1 | 4 | 7 |
| [privacyguard/infrastructure/persona/json\_persona\_repository.py](/privacyguard/infrastructure/persona/json_persona_repository.py) | Python | 136 | 16 | 22 | 174 |
| [privacyguard/infrastructure/pii/\_\_init\_\_.py](/privacyguard/infrastructure/pii/__init__.py) | Python | 2 | 1 | 4 | 7 |
| [privacyguard/infrastructure/pii/gliner\_adapter.py](/privacyguard/infrastructure/pii/gliner_adapter.py) | Python | 46 | 6 | 11 | 63 |
| [privacyguard/infrastructure/pii/rule\_based\_detector.py](/privacyguard/infrastructure/pii/rule_based_detector.py) | Python | 4,006 | 111 | 168 | 4,285 |
| [privacyguard/infrastructure/rendering/\_\_init\_\_.py](/privacyguard/infrastructure/rendering/__init__.py) | Python | 16 | 1 | 3 | 20 |
| [privacyguard/infrastructure/rendering/fill\_strategies.py](/privacyguard/infrastructure/rendering/fill_strategies.py) | Python | 354 | 26 | 72 | 452 |
| [privacyguard/infrastructure/rendering/prompt\_renderer.py](/privacyguard/infrastructure/rendering/prompt_renderer.py) | Python | 113 | 10 | 13 | 136 |
| [privacyguard/infrastructure/rendering/screenshot\_renderer.py](/privacyguard/infrastructure/rendering/screenshot_renderer.py) | Python | 930 | 50 | 77 | 1,057 |
| [privacyguard/infrastructure/restoration/\_\_init\_\_.py](/privacyguard/infrastructure/restoration/__init__.py) | Python | 2 | 1 | 4 | 7 |
| [privacyguard/infrastructure/restoration/action\_restorer.py](/privacyguard/infrastructure/restoration/action_restorer.py) | Python | 30 | 3 | 5 | 38 |
| [privacyguard/utils/\_\_init\_\_.py](/privacyguard/utils/__init__.py) | Python | 11 | 1 | 3 | 15 |
| [privacyguard/utils/aho\_matcher.py](/privacyguard/utils/aho_matcher.py) | Python | 65 | 3 | 13 | 81 |
| [privacyguard/utils/image.py](/privacyguard/utils/image.py) | Python | 34 | 9 | 12 | 55 |
| [privacyguard/utils/pii\_value.py](/privacyguard/utils/pii_value.py) | Python | 650 | 19 | 87 | 756 |
| [privacyguard/utils/text.py](/privacyguard/utils/text.py) | Python | 8 | 3 | 7 | 18 |

[Summary](results.md) / Details / [Diff Summary](diff.md) / [Diff Details](diff-details.md)