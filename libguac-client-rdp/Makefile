BUILD=build
UPDATE=update.tmp
TARGET=libguac-client-rdp
# set this to 'echo' to not do svn commands
SVNFAKE=echo

all: 
	@echo "This target cannot be built this way. Use:"
	@echo "   'make update' to update the ${TARGET} directory"	
	@echo "   'cd ${TARGET}', then normal make commands to make ${TARGET}"	

update:	
	/bin/rm -rf ${UPDATE} && \
	/bin/mkdir -p ${UPDATE} && \
	( cd ${UPDATE} && \
	git clone -b debian git://guacamole.git.sourceforge.net/gitroot/guacamole/${TARGET} && \
	cd ${TARGET} && \
	git remote add alex git://git.alex.org.uk/${TARGET}.git && \
	git remote update && \
	git merge alex/master && \
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

