Detection Engineering Lab

This repository documents the development of my personal detection engineering lab, focused on understanding how modern security operations teams monitor, detect, and respond to threats.

The lab environment is designed to simulate realistic enterprise-style logging and security monitoring scenarios using virtualised systems.

Lab Architecture

The lab is built using:

Proxmox for virtualization

Windows virtual machines for log generation

Ubuntu-based systems for analysis

Splunk for log ingestion, search, and detection development

The goal is to replicate a simplified SOC environment where security events can be generated, ingested, analysed, and investigated.

Current Focus Areas

Windows authentication logging and event analysis

Log ingestion and parsing in Splunk

Detection query development (SPL)

Alert logic tuning and reduction of false positives

Basic incident investigation workflows

Documentation of findings and response reasoning

Rather than focusing on tool collection, this lab focuses on understanding detection logic and structured investigation.

Example Learning Scenarios

Simulating failed authentication activity and analysing related security events

Reviewing process execution logs and identifying suspicious behaviour

Building threshold-based and behaviour-based detection queries

Writing short investigation summaries based on observed log activity

Objective

The objective of this lab is to build a strong foundation in security operations and detection engineering by:

Understanding how attacks appear in logs

Learning how to design effective detection logic

Developing structured thinking for incident response

Practicing clear documentation of technical findings

This lab is continuously evolving as new scenarios are tested and detection logic is refined.
