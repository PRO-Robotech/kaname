// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {validatePermitFrame}=require('./run-rid-native.cjs');
for(const [name,raw,ended,want] of [
 ['exact-frame-EOF','RID_NEWMAN_PERMIT_V1\n',true,true],
 ['missing-frame-EOF','',true,false],
 ['wrong-frame','WRONG\n',true,false],
 ['extra-frame','RID_NEWMAN_PERMIT_V1\nRID_NEWMAN_PERMIT_V1\n',true,false],
 ['extra-byte','RID_NEWMAN_PERMIT_V1\nx',true,false],
 ['no-EOF','RID_NEWMAN_PERMIT_V1\n',false,false],
])test('permit/'+name,()=>{if(want)assert.doesNotThrow(()=>validatePermitFrame(raw,ended));else assert.throws(()=>validatePermitFrame(raw,ended));});
