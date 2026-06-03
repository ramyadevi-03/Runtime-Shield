import sys
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig

    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()

    text = "Hello, my email is marty.mcfly@gmail.com, phone is 555-0199, SSN is 999-12-3456, and credit card is 1234-5678-9012-3456."
    
    results = analyzer.analyze(text=text, language="en")
    print("Detected entities:")
    for res in results:
        print(f" - {res.entity_type}: score={res.score}, start={res.start}, end={res.end}")

    operators = {
        "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[REDACTED-EMAIL]"}),
        "US_SSN": OperatorConfig("replace", {"new_value": "[REDACTED-SSN]"}),
        "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[REDACTED-PHONE]"}),
        "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[REDACTED-CC]"}),
    }

    anonymized = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
    print("\nAnonymized result:")
    print(anonymized.text)
    print("\nPresidio verification complete!")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
