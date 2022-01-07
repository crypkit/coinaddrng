all: help

help: 
	@echo 'NAME'
	@echo '    Makefile for coinaddrvalid'
	@echo ''
	@echo 'SYNOPSIS'
	@echo '    make [options]'
	@echo ''
	@echo 'DESCRIPTION'
	@echo '    help                 show help'
	@echo ''
	@echo '    dist                 builds both binary and source distribution'
	@echo ''
	@echo '    install              installs coinaddrvalid library'
	@echo ''
	@echo '    uninstall            uninstalls coinaddrvalid library'

install:
	pip3 install --upgrade .


uninstall:
	pip3 uninstall -y coinaddrvalid


dist:
	rm -f dist/*
	python3 setup.py sdist bdist_wheel
	pip3 install --upgrade twine
	python3 -m twine upload dist/*

.PHONY: dist