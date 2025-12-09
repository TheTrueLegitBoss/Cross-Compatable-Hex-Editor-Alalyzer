from setuptools import setup

setup(
    name="CrossCompatHexEditorAnalyzer",
    version="1.0.0",
    description="Cross-Platform Hex Editor and Analyzer with Malware Detection and PE/ELF Support",
    author="TheTrueLegitBoss",
    author_email="your@email.com",
    url="https://github.com/TheTrueLegitBoss/Cross-Compatable-Hex-Editor-Alalyzer",
    py_modules=["HexEditor"],
    entry_points={
        "console_scripts": [
            "hexeditor = HexEditor:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Utilities",
        "Topic :: Software Development :: Debuggers",
        "Topic :: System :: Operating System",
    ],
    python_requires='>=3.7',
)
