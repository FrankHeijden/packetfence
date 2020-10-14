import { BaseFormGroupArrayDraggable, BaseFormGroupArrayDraggableProps } from '@/components/new'
import BaseRuleCondition from './BaseRuleCondition'
import i18n from '@/utils/locale'

export const props = {
  ...BaseFormGroupArrayDraggableProps,

  buttonLabel: {
    type: String,
    default: i18n.t('Add Condition')
  },
// overload :draggableComponent
  draggableComponent: {
    type: Object,
    default: () => BaseRuleCondition
  },
  // overload :defaultItem
  defaultItem: {
    type: Object,
    default: () => ({
      attribute: null,
      operator: null,
      value: null
    })
  },
  // overload draggable handlers
  onAdd: {
    type: Function,
    default: (context, index, newComponent) => {
      const { onExpand = () => {} } = newComponent
      onExpand()
    }
  },
  onCopy: {
    type: Function,
    default: (context, fromIndex, toIndex, fromComponent, toComponent) => {
      const { isCollapse } = fromComponent
      if (!isCollapse) {
        const { onExpand = () => {} } = toComponent
        onExpand()
      }
    }
  }
}

export default {
  name: 'base-rule-form-group-conditions',
  extends: BaseFormGroupArrayDraggable,
  props
}
