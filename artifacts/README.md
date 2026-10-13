# Generated artifacts

Store trained model bundles in `models/` and throwaway outputs in `tmp/`; both are ignored by Git. A bundle must include parameters, feature specification and vocabulary, language, model version, chosen threshold, dataset/split hashes, and compatibility information. The scanner will load a frozen bundle and will not train during a scan.
