all: help

help: 
	@echo 'NAME'
	@echo '    Makefile for coinaddrng'
	@echo ''
	@echo 'SYNOPSIS'
	@echo '    make [options]'
	@echo ''
	@echo 'DESCRIPTION'
	@echo '    help                 show help'
	@echo ''
	@echo '    dist                 builds both binary and source distribution'
	@echo ''
	@echo '    install              installs blockapi library'
	@echo ''
	@echo '    uninstall            uninstalls blockapi library'

install:
	pip3 install --upgrade .


uninstall:
	pip3 uninstall -y coinaddrng


dist:
	rm -f dist/*
	python3 setup.py sdist bdist_wheel
	pip3 install --upgrade twine
	python3 -m twine upload dist/*

.PHONY: dist