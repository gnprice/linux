/*
 * Copyright 2012 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Ben Skeggs
 */

#include <core/os.h>
#include <core/class.h>
#include <core/engctx.h>

#include <engine/software.h>

struct nv10_software_priv {
	struct nouveau_software base;
};

struct nv10_software_chan {
	struct nouveau_software_chan base;
};

/*******************************************************************************
 * software object classes
 ******************************************************************************/

static int
nv10_software_flip(struct nouveau_object *object, u32 mthd,
		   void *args, u32 size)
{
	struct nv10_software_chan *chan = (void *)nv_engctx(object->parent);
	if (chan->base.flip)
		return chan->base.flip(chan->base.flip_data);
	return -EINVAL;
}

static struct nouveau_omthds
nv10_software_omthds[] = {
	{ 0x0500, nv10_software_flip },
	{}
};

static struct nouveau_oclass
nv10_software_sclass[] = {
	{ 0x016e, &nouveau_object_ofuncs, nv10_software_omthds },
	{}
};

/*******************************************************************************
 * software context
 ******************************************************************************/

static int
nv10_software_context_ctor(struct nouveau_object *parent,
		      struct nouveau_object *engine,
		      struct nouveau_oclass *oclass, void *data, u32 size,
		      struct nouveau_object **pobject)
{
	struct nv10_software_chan *chan;
	int ret;

	ret = nouveau_software_context_create(parent, engine, oclass, &chan);
	*pobject = nv_object(chan);
	if (ret)
		return ret;

	return 0;
}

static struct nouveau_oclass
nv10_software_cclass = {
	.handle = NV_ENGCTX(SW, 0x04),
	.ofuncs = &(struct nouveau_ofuncs) {
		.ctor = nv10_software_context_ctor,
		.dtor = _nouveau_software_context_dtor,
		.init = _nouveau_software_context_init,
		.fini = _nouveau_software_context_fini,
	},
};

/*******************************************************************************
 * software engine/subdev functions
 ******************************************************************************/

static int
nv10_software_ctor(struct nouveau_object *parent, struct nouveau_object *engine,
	      struct nouveau_oclass *oclass, void *data, u32 size,
	      struct nouveau_object **pobject)
{
	struct nv10_software_priv *priv;
	int ret;

	ret = nouveau_software_create(parent, engine, oclass, &priv);
	*pobject = nv_object(priv);
	if (ret)
		return ret;

	nv_engine(priv)->cclass = &nv10_software_cclass;
	nv_engine(priv)->sclass = nv10_software_sclass;
	nv_subdev(priv)->intr = nv04_software_intr;
	return 0;
}

struct nouveau_oclass
nv10_software_oclass = {
	.handle = NV_ENGINE(SW, 0x10),
	.ofuncs = &(struct nouveau_ofuncs) {
		.ctor = nv10_software_ctor,
		.dtor = _nouveau_software_dtor,
		.init = _nouveau_software_init,
		.fini = _nouveau_software_fini,
	},
};
