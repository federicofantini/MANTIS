from setuptools import setup, find_packages # type: ignore

setup(
    name="MANTIS",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "dotenv",
        "aiohttp",
        "av",
        "opencv-python",
        "opencv-contrib-python",
        "Pillow",
        "matrix-nio",
        "matrix-nio[e2e]",
        "slixmpp",
        "slixmpp-omemo",
    ],
    entry_points={
        'console_scripts': [
            'MANTIS=mantis.main:main',
        ],
    },
    author="Federico Fantini",
    url="https://github.com/federicofantini/mantis",
    description="MANTIS is a lightweight motion detection system designed for Raspberry Pi, aimed at providing real-time surveillance and alerting capabilities without giving up privacy.",
    license="GPL-3.0-or-later",
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)