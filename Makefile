.PHONY: test demo media lint
test:
	python3 -m unittest discover -s tests -t .
demo:
	python3 plugins/network-doctor/skills/network-doctor/scripts/netdoc.py diagnose --demo
media:
	python3 docs/media/src/make_svgs.py
	for t in diagnose call-under-load router; do vhs docs/media/tapes/$$t.tape; done
	bash docs/media/src/make_hero.sh
	cp docs/media/build/hero.mp4 docs/media/hero.mp4

site:
	bash site/build.sh
