B1;2cBUILD=build
UPDATE=update.tmp
TARGET=guacd
# set this to 'echo' to not do svn commands
SVNFAKE=

all: 
	@echo "This target cannot be built this way. Use:"
	@echo "   'make update' to update the ${TARGET} directory"	
	@echo "   'cd ${TARGET}', then normal make commands to make ${TARGET}"	

update:	
	/bin/rm -rf ${UPDATE} && \
	/bin/mkdir -p ${UPDATE} && \
	( cd ${UPDATE} && \
	git clone -b debian git://guacamole.git.sourceforge.net/gitroot/guacamole/guacd && \
	cd ${TARGET} && \
	git remote add alex git://git.alex.org.uk/guacd.git && \
	git remote update && \
	git merge alex/master && \
	/bin/echo -e "\nexit 0\n" >> debian/preinst && \
	/bin/echo -e "#!/bin/bash\necho \"exit 0\" >/etc/default/guacd" > debian/postinst && \
	cat ../../changelog.delta debian/changelog > debian/changelog.new && \
	mv debian/changelog.new debian/changelog && \
	/bin/rm -rf .git ) && \
	( if [ -d ${TARGET} ] ; then ${SVNFAKE} svn rm --force ${TARGET} ; fi )  && \
	rm -rf ${TARGET} && \
	echo "Moving new target into place"
	mv ${UPDATE}/${TARGET} ${TARGET}
	${SVNFAKE} svn add ${TARGET}
	(cd ${TARGET} && perl -p -i -e 's/-1ubuntu2flexiant/.2-1flexiant/g;' debian/changelog)
	/bin/rm -rf ${UPDATE}

clean:
	/bin/rm -rf ${BUILD} ${UPDATE}

