import styled from 'styled-components';
import { colors } from '../../config.json';
import * as Cell from './cell';
import { NavigationScrollbars } from './NavigationBar';
import Selector from './cell/Selector';

export const StyledInputFrame = styled(Cell.InputFrame)({
  flex: 0,
});

export const StyledSelectorContainer = styled.div({
  flex: 0,
});

export const StyledSelectorForFooter = (styled(Selector)({
  marginBottom: 0,
}) as unknown) as new <T>() => Selector<T>;

export const StyledTunnelProtocolContainer = styled(StyledSelectorContainer)({
  marginBottom: '20px',
});

export const StyledNavigationScrollbars = styled(NavigationScrollbars)({
  flex: 1,
});

export const StyledNoWireguardKeyErrorContainer = styled(Cell.Footer)({
  paddingBottom: 0,
});

export const StyledNoWireguardKeyError = styled(Cell.FooterText)({
  fontWeight: 800,
  color: colors.red,
});

export const StyledCustomDnsSwitchContainer = styled(Cell.Container)({
  marginBottom: '1px',
});

export const StyledCustomDnsFooter = styled(Cell.Footer)({
  marginBottom: '2px',
});

export const StyledAddCustomDnsButton = styled(Cell.CellButton)({
  backgroundColor: colors.blue40,
});

export const StyledAddCustomDnsLabel = styled(Cell.Label)(
  {},
  (props: { paddingLeft?: number }) => ({
    fontFamily: 'Open Sans',
    fontWeight: 'normal',
    fontSize: '16px',
    paddingLeft: (props.paddingLeft ?? 32) + 'px',
    whiteSpace: 'pre-wrap',
    overflowWrap: 'break-word',
    width: '171px',
    marginRight: '25px',
  }),
);
